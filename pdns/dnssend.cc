/*
 * This file is part of PowerDNS or dnsdist.
 * Copyright -- PowerDNS.COM B.V. and its contributors
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * In addition, for the avoidance of any doubt, permission is granted to
 * link this program with OpenSSL and to (re)distribute the binaries
 * produced as the result of such linking.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#define __FAVOR_BSD
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "statbag.hh"
#include "dnspcap.hh"
#include "dnsrecords.hh"
#include "dnsparser.hh"
#include <boost/tuple/tuple.hpp>
#include <boost/tuple/tuple_comparison.hpp>
#include <map>
#include <set>
#include <fstream>
#include <algorithm>
#include "anadns.hh"

#include "namespaces.hh"
#include "namespaces.hh"

StatBag S;

struct tm* pdns_localtime_r(const uint32_t* then, struct tm* tm)
{
  time_t t = *then;
  
  return localtime_r(&t, tm);
}

int32_t g_clientQuestions, g_clientResponses, g_serverQuestions, g_serverResponses, g_skipped;
struct pdns_timeval g_lastanswerTime, g_lastquestionTime;
void makeReport(const struct pdns_timeval& tv)
{
  int64_t clientdiff = g_clientQuestions - g_clientResponses;
  int64_t serverdiff = g_serverQuestions - g_serverResponses;

  if(clientdiff > 1 && clientdiff > 0.02*g_clientQuestions) {
    char tmp[80];
    struct tm tm=*pdns_localtime_r(&tv.tv_sec, &tm);
    strftime(tmp, sizeof(tmp) - 1, "%F %H:%M:%S", &tm);

    cout << tmp << ": Resolver dropped too many questions (" 
         << g_clientQuestions <<" vs " << g_clientResponses << "), diff: " <<clientdiff<<endl;

    tm=*pdns_localtime_r(&g_lastanswerTime.tv_sec, &tm);
    strftime(tmp, sizeof(tmp) - 1, "%F %H:%M:%S", &tm);
    
    cout<<"Last answer: "<<tmp<<"."<<g_lastanswerTime.tv_usec/1000000.0<<endl;

    tm=*pdns_localtime_r(&g_lastquestionTime.tv_sec, &tm);
    strftime(tmp, sizeof(tmp) - 1, "%F %H:%M:%S", &tm);
    
    cout<<"Last question: "<<tmp<<"."<<g_lastquestionTime.tv_usec/1000000.0<<endl;
  }

  if(serverdiff > 1 && serverdiff > 0.02*g_serverQuestions) {
    char tmp[80];
    struct tm tm=*pdns_localtime_r(&tv.tv_sec, &tm);
    strftime(tmp, sizeof(tmp) - 1, "%F %H:%M:%S", &tm);

    cout << tmp << ": Auth server dropped too many questions (" 
         << g_serverQuestions <<" vs " << g_serverResponses << "), diff: " <<serverdiff<<endl;

    tm=*pdns_localtime_r(&g_lastanswerTime.tv_sec, &tm);
    strftime(tmp, sizeof(tmp) - 1, "%F %H:%M:%S", &tm);
    
    cout<<"Last answer: "<<tmp<<"."<<g_lastanswerTime.tv_usec/1000000.0<<endl;

    tm=*pdns_localtime_r(&g_lastquestionTime.tv_sec, &tm);
    strftime(tmp, sizeof(tmp) - 1, "%F %H:%M:%S", &tm);
    
    cout<<"Last question: "<<tmp<<"."<<g_lastquestionTime.tv_usec/1000000.0<<endl;
  }
//  cout <<"Recursive questions: "<<g_clientQuestions<<", recursive responses: " << g_clientResponses<< 
//    ", server questions: "<<g_serverQuestions<<", server responses: "<<g_serverResponses<<endl;


//  cerr << tv.tv_sec << " " <<g_clientQuestions<<" " << g_clientResponses<< " "<<g_serverQuestions<<" "<<g_serverResponses<<" "<<g_skipped<<endl;
  g_clientQuestions=g_clientResponses=g_serverQuestions=g_serverResponses=0;
  g_skipped=0;
}

void usage() {
  cerr<<"syntax: dnssend INFILE destination usec"<<endl;
}

int main(int argc, char** argv)
try
{
  // Parse possible options
  if (argc == 1) {
    usage();
    return EXIT_SUCCESS;
  }

  for(int n=1 ; n < argc; ++n) {
    if ((string) argv[n] == "--help") {
      usage();
      return EXIT_SUCCESS;
    }

    if ((string) argv[n] == "--version") {
      cerr<<"dnsgram "<<VERSION<<endl;
      return EXIT_SUCCESS;
    }
  }

  ComboAddress dest(argv[2]);
  uint32_t snooze=atoi(argv[3]);
   
  reportAllTypes();
  for(int n=1 ; n < 2; ++n) {
    cout<<argv[n]<<endl;
    unsigned int parseErrors=0, totalQueries=0, skipped=0;
    PcapPacketReader pr(argv[n]);
    //    PcapPacketWriter pw(argv[n]+string(".out"), pr);
    /* four sorts of packets: 
       "rd": question from a client pc
       "rd qr": answer to a client pc
       "": question from the resolver
       "qr": answer to the resolver */
    
    /* what are interesting events to note? */
    /* we measure every 60 seconds, each interval with 10% less answers than questions is interesting */
    /* report chunked */
    

 
    int count=0;
    while(pr.getUDPPacket()) {
      if((ntohs(pr.d_udp->uh_dport)==5300 || ntohs(pr.d_udp->uh_sport)==5300 ||
          ntohs(pr.d_udp->uh_dport)==53   || ntohs(pr.d_udp->uh_sport)==53) &&
         pr.d_len > 12) {
        try {
	  struct dnsheader *hdr=(struct dnsheader*)pr.d_payload;

          if(!hdr->rd || hdr->qr) 
	    continue;

	  int sock=socket(AF_INET, SOCK_DGRAM, 0);
	  SSetsockopt(sock, IPPROTO_IP , IP_TRANSPARENT, 1);
	  SBind(sock, pr.getSource());
	  sendto(sock, pr.d_payload, pr.d_len, 0, (struct sockaddr*)&dest, dest.getSocklen());
	  close(sock);
	  if(!(++count % 1024))
	    usleep(snooze);
        }
        catch(std::exception& e) {
          cerr << e.what() << endl;
          continue;
        }
      }
    }
  }
}
catch(std::exception& e)
{
  cerr<<"Fatal: "<<e.what()<<endl;
}
