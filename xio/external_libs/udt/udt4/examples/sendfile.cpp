#ifndef WIN32
   #include <cstdlib>
#else
   #include <winsock2.h>
   #include <ws2tcpip.h>
#endif
#include <fstream>
#include <iostream>
#include <cstring>
#include <udt.h>

using namespace std;

int main(int argc, char* argv[])
{
   //usage: sendfile [server_port]
   if ((2 < argc) || ((2 == argc) && (0 == atoi(argv[1]))))
   {
      cout << "usage: sendfile [server_port]" << endl;
      return 0;
   }

   // use this function to initialize the UDT library
   UDT::startup();

   UDTSOCKET serv = UDT::socket(AF_INET, SOCK_STREAM, 0);

   // Windows UDP issue
   // For better performance, modify HKLM\System\CurrentControlSet\Services\Afd\Parameters\FastSendDatagramThreshold
#ifdef WIN32
   int mss = 1052;
   UDT::setsockopt(serv, 0, UDT_MSS, &mss, sizeof(int));
#endif

   int port = 9000;
   if (2 == argc)
      port = atoi(argv[1]);

   sockaddr_in my_addr;
   my_addr.sin_family = AF_INET;
   my_addr.sin_port = htons(port);
   my_addr.sin_addr.s_addr = INADDR_ANY;
   memset(&(my_addr.sin_zero), '\0', 8);

   if (UDT::ERROR == UDT::bind(serv, (sockaddr*)&my_addr, sizeof(my_addr)))
   {
      cout << "bind: " << UDT::getlasterror().getErrorMessage() << endl;
      return 0;
   }

   cout << "server is ready at port: " << port << endl;

   UDT::listen(serv, 1);

   sockaddr_in their_addr;
   int namelen = sizeof(their_addr);

   UDTSOCKET fhandle;

   if (UDT::INVALID_SOCK == (fhandle = UDT::accept(serv, (sockaddr*)&their_addr, &namelen)))
   {
      cout << "accept: " << UDT::getlasterror().getErrorMessage() << endl;
      return 0;
   }

   UDT::close(serv);

   // aquiring file name information from client
   char file[1024];
   int len;

   if (UDT::ERROR == UDT::recv(fhandle, (char*)&len, sizeof(int), 0))
   {
      cout << "recv: " << UDT::getlasterror().getErrorMessage() << endl;
      return 0;
   }

   if (UDT::ERROR == UDT::recv(fhandle, file, len, 0))
   {
      cout << "recv: " << UDT::getlasterror().getErrorMessage() << endl;
      return 0;
   }
   file[len] = '\0';

   // open the file
   fstream ifs(file, ios::in | ios::binary);

   ifs.seekg(0, ios::end);
   int64_t size = ifs.tellg();
   ifs.seekg(0, ios::beg);

   // send file size information
   if (UDT::ERROR == UDT::send(fhandle, (char*)&size, sizeof(int64_t), 0))
   {
      cout << "send: " << UDT::getlasterror().getErrorMessage() << endl;
      return 0;
   }

   UDT::TRACEINFO trace;
   UDT::perfmon(fhandle, &trace);

   // send the file
   if (UDT::ERROR == UDT::sendfile(fhandle, ifs, 0, size))
   {
      cout << "sendfile: " << UDT::getlasterror().getErrorMessage() << endl;
      return 0;
   }

   UDT::perfmon(fhandle, &trace);
   cout << "speed = " << trace.mbpsSendRate << "Mbits/sec" << endl;

   UDT::close(fhandle);

   ifs.close();

   // use this function to release the UDT library
   UDT::cleanup();

   return 1;
}
