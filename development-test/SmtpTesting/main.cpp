#define _CRT_SECURE_NO_WARNINGS 
#include <stdio.h>
#include <string.h>
#include <malloc.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>          /* See NOTES */
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h> /* superset of previous */
#include <arpa/inet.h>
#include <errno.h>
#include "read_buffer.h"
#include "slab_allocator.h"

struct slaballoc_state slaballoc;

enum smtp_state {
	NoCommand = 0,
	NoCommandNotData,
	DataCommand
};

struct spam_check_entry {
	/* packet ID for delivering verdict */
	unsigned int nfpacket_id;

	/* socket to spamassassin */
	int socket;

	union {
		struct {
			/* the message data */
			slab_buffer* message;

			/* size of message so far */
			uint32_t message_size;

			/* position in the current buffer */
			uint16_t message_buffer_pos;
		} writing;

		struct {
			/* state of parsing the response from spamassassin */
			enum {
				read_state_first_line = 0,
				read_state_second_line,
				read_state_spam
			} state;
		} reading;
	};
};

struct smtp_entry {
	/*
	The currently active command
	*/
	smtp_state state;

	/* chain of data to be written to spamassassin */
	slab_buffer* out;
	slab_buffer* last;

	/* size of message so far */
	uint32_t message_size;

	/*
	A buffer for partial sequences of "\n.\n" end marker
	At most this will contain "\n.\r\0" for end markers
	or "DATA\0" for data search
	*/
	char seq_buffer[5];

	/*
	Did the ending marker have a \r?
	*/
	unsigned cr_prefixed : 1;

	/*
	Index of seq_buffer currently active
	*/
	unsigned seq_buffer_idx : 3;

};

void smtp_store_message(const char* buffer, unsigned int buffer_length, struct smtp_entry& entry){
	uint16_t can_write, to_write;
	while (buffer_length){
		can_write = SLAB_SIZE - entry.last->used;
		to_write = (can_write > buffer_length) ? buffer_length : can_write;

		memcpy(((char*)entry.last->buffer) + entry.last->used, buffer, to_write);

		buffer_length -= to_write;
		entry.last->used += to_write;

		if (buffer_length){
			slab_buffer* next = slab_buffer_alloc(&slaballoc);
			entry.last->next = next;
			entry.last = next;
		}
	}
}

void log_error(const char* errstr){
	printf("Error: %s\n", errstr);
}

typedef enum {
	message_complete, needs_more, continue_processing
} state_action;


state_action _smtp_feed(smtp_entry& state, struct read_buffer& rb, const char* start, int end){
	unsigned int stored_data = 0;
	int n = end;

	for (const char* buffer = start; n; buffer++, n--){
		char c = *buffer;

		if (state.state == NoCommand){
			//We only care about DATA commands, so just keep skipping through until then
			if (state.seq_buffer_idx == 0){
				if (c == 'D' || c == 'd'){
					state.seq_buffer[0] = c;
					state.seq_buffer_idx++;
				}else if (c != '\n'){
					state.state = NoCommandNotData;
				}
			}
			else{
				if (((c == 'A' || c == 'a') && state.seq_buffer_idx == 1)
					|| ((c == 'T' || c == 't') && state.seq_buffer_idx == 2)
					|| (c == 'A' || c == 'a') && state.seq_buffer_idx == 3
					){
					state.seq_buffer[state.seq_buffer_idx++] = c;
				}
				else if (c == '\n' && state.seq_buffer_idx == 4){
					state.state = DataCommand;
#ifdef DEBUG_BUILD
					memset(state.seq_buffer, 0, sizeof(state.seq_buffer));
#endif
					state.seq_buffer_idx = 0;
					start = buffer + 1;
					state.last = state.out = slab_buffer_alloc(&slaballoc);
				}
				else if (c != '\r' && state.seq_buffer_idx == 4){
#ifdef DEBUG_BUILD
					memset(state.seq_buffer, 0, sizeof(state.seq_buffer));
#endif
					state.seq_buffer_idx = 0;
					state.state = NoCommandNotData;
				}
			}
		}
		else if (state.state == NoCommandNotData){
			//We dont care what happens here this command cant be DATA, wait until new line
			if (c == '\n'){
				state.state = NoCommand;
			}
		}
		else{ //Data Command
			bool is_marker = false;
			if (c == '\r'){
				state.cr_prefixed = true;
			}
			else if (state.seq_buffer_idx == 0 && state.cr_prefixed){
				state.cr_prefixed = false;
			}
			if (c == '\n'){
				//Valid at indexes 0, 2 or 3
				//Combinations: "\n", "\n.\n", "\n.\r\n"

				if (state.seq_buffer_idx == 0){//First newline
					is_marker = true;

					//If we have any stored data lets push it to spamassasin now 
					if (stored_data){
						smtp_store_message(start, stored_data, state);
						start += stored_data;
						stored_data = 0;
					}
				}
				else if (state.seq_buffer_idx != 1){//Final newline
					//This is the end of the command, the marker was valid
					start = buffer + 1;
					state.state = NoCommand;
					return message_complete;
				}
				else{
					//Not an end marker
					is_marker = false;
				}
			}
			else if (c == '.'){
				if (state.seq_buffer_idx == 1){
					is_marker = true;
				}
				else{
					//Not an end marker
					is_marker = false;
				}
			}
			else if (c == '\r'){
				if (state.seq_buffer_idx == 2){
					is_marker = true;
				}
			}

			if (is_marker){
				//Increment marker position and store character
				state.seq_buffer[state.seq_buffer_idx++] = c;
				start++;
			}
			else{
				if (stored_data != 0){
					if (state.seq_buffer_idx != 0){
						smtp_store_message(start, stored_data, state);
						start += stored_data;
						stored_data = 0;
					}
				}

				if (state.seq_buffer_idx != 0){
					//Push a CR
					if (state.cr_prefixed){
						smtp_store_message("\r", 1, state);
					}

					//Push what we thought was the marker
					smtp_store_message(state.seq_buffer, state.seq_buffer_idx, state);

					//Reset marker position
					state.seq_buffer_idx = 0;
				}

				stored_data++;
			}
		}
	}

	if (stored_data != 0){
		smtp_store_message(start, stored_data, state);
		start += stored_data;
		stored_data = 0;
	}

	RBUF_READMOVE(rb, end);

	return needs_more;
}

state_action smtp_feed(smtp_entry& state, struct read_buffer& rb){
	char* buffer;
	int end, n;
	state_action ret = continue_processing;

	// Process new data
	RBUF_ITERATE(rb, n, buffer, end, ret, _smtp_feed(state, rb, buffer, end));

	return ret;
}

int spam_get_connection(){
	int fd, rc;
	struct sockaddr_in serveraddr;

	if ((fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
		perror("socket() error");
		return -1;
	}

	/*If the server hostname is supplied*/

	memset(&serveraddr, 0, sizeof(struct sockaddr_in));
	serveraddr.sin_family = AF_INET;
	serveraddr.sin_port = htons(783);
	serveraddr.sin_addr.s_addr = inet_addr("127.0.0.1");

	/* After the socket descriptor is received, the */
	/* connect() function is used to establish a */
	/* connection to the server. */
	/***********************************************/
	/* connect() to server. */
	if ((rc = connect(fd, (struct sockaddr *)&serveraddr, sizeof(serveraddr))) < 0)
	{
		perror("Client-connect() error");
		close(fd);
		return -1;
	}

	return fd;
}

void spam_check_init(struct spam_check_entry* entry){
	//Create request
	struct slab_buffer* next = slab_buffer_alloc(&slaballoc);
	next->used = snprintf((char*)next->buffer, SLAB_SIZE, "CHECK SPAMC/1.2\nContent-length: %u\n\n", entry->writing.message_size);
	next->next = entry->writing.message;
	entry->writing.message = next;

	//Connect to spamassassin
	entry->socket = spam_get_connection();
}

/*
Output to spamassassin
Returns true if there is more to do
Returns false if this is the end (error or completion of sending)
*/
bool spam_write(struct spam_check_entry* entry){
	struct slab_buffer* buffer;
	int rc;

	do {
		buffer = entry->writing.message;

		rc = write(entry->socket, &((char*)buffer->buffer)[entry->writing.message_buffer_pos], buffer->used);
		if (rc >= 0){
			buffer->used -= rc;

			if (buffer->used == 0){
				//Everything written, move to the next link
				buffer = entry->writing.message->next;
				slab_buffer_free(&slaballoc, entry->writing.message);
				entry->writing.message = buffer;
				entry->writing.message_buffer_pos = 0;
			}
			else{
				//Couldnt write it all
				entry->writing.message_buffer_pos += rc;
				return true;
			}
		}
		else{
			//Error cases
			if (rc == 0 || (rc == -1 && (errno == EAGAIN || errno == EWOULDBLOCK))){
				return true;
			}
			else{
				//error
				return false;
			}
		}
	} while (buffer != NULL);

	return false;
}

bool spam_read(struct spam_check_entry* entry, bool* is_spam_result){
	char buffer[128];
	char* buffer_ptr = buffer;
	int len;

	*is_spam_result = false;
	/*
	SPAMD/1.1 0 EX_OK
	Spam: False ; 0.6 / 5.0
	*/
	len = read(entry->socket, buffer, sizeof(buffer));
	if (len == 0 || (len == -1 && (errno == EAGAIN || errno == EWOULDBLOCK))){
		return true;
	}
	else if (len == -1){
		//error
		perror("read error");
		return false;
	}
	while (len){
		char c = *buffer_ptr;
		if (entry->reading.state == entry->reading.read_state_first_line){
			//TODO: parse for EX_OK
			if (c == '\n'){
				entry->reading.state = entry->reading.read_state_second_line;
			}
		}
		else if (entry->reading.state == entry->reading.read_state_second_line){
			if (c == ':'){
				entry->reading.state = entry->reading.read_state_spam;
			}
		}
		else{
			if (c=='F'){//*F*alse
				return false;
			}
			else if (c == 'T'){//*T*rue
				*is_spam_result = true;
				return false;
			}
		}

		buffer_ptr++;
		len--;
	}

	return true;
}

int main(int argc, char** argv){
	if (argc != 2){
		printf("Usage: SmtpTesting [filename]\nTakes a file containing a full SMTP transaction (what the client sends).\n");
		return 1;
	}

	const char* path = argv[1];
	slaballoc.free_buffers = NULL;
	
	char file_buffer[100];
	struct read_buffer buffer;
	rbuf_init(&buffer);

	smtp_entry state;
	memset(&state, 0, sizeof(state));

	FILE* fp = fopen(path, "r");
	//while (fgets((char*)buffer_write_pos, max_read, fp) != NULL){
	int len;
	while ((len = fread(file_buffer, sizeof(char), 100, fp)) != 0){
		rbuf_writen(&buffer, file_buffer, len);

		//int len = strlen(buffer);
		state_action action_to_perform = smtp_feed(state, buffer);
		if (action_to_perform == message_complete){
			//Create a spamassasin check
			spam_check_entry entry;
			entry.writing.message = state.out;
			entry.writing.message_size = state.message_size;

			//Reset smtp state
			state.message_size = 0;
			state.last = state.out = NULL;

			//Init spam check
			spam_check_init(&entry);

			//Write out message
			bool need_to_write;
			do {
				need_to_write = spam_write(&entry);
			} while (need_to_write);

			if (!need_to_write && entry.writing.message != NULL){
				//error
				printf("An error occured while witing the message to spamassassin\n");
			}

			//Read result
			entry.reading.state = entry.reading.read_state_first_line;
			bool need_to_read, result;
			do {
				need_to_read = spam_read(&entry, &result);
			} while (need_to_write);
			
			//Output
			printf("is spam: %d", result);
		}
	}

	if (state.state != NoCommand){
		printf("Parser did not compete a valid transaction!\n");
	}

	return 0;
}