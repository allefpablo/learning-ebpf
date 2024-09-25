struct data_t {
   int pid;
   int uid;
   char command[16];
   char message[12];
   char path[16];
};

struct user_msg_t {
   char message[12];
};