#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <string.h>
//#include <malloc.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>
#include <rte_mbuf.h>
#include "dns.h"

static const uint32_t QR_MASK = 0x8000;
static const uint32_t OPCODE_MASK = 0x7800;
static const uint32_t AA_MASK = 0x0400;
static const uint32_t TC_MASK = 0x0200;
static const uint32_t RD_MASK = 0x0100;
static const uint32_t RA_MASK = 0x8000;
static const uint32_t RCODE_MASK = 0x000F;


static int get_A_Record(uint8_t addr[4], const char domain_name[])
{
  if (strcmp("foo.bar.com", domain_name) == 0) {
    addr[0] = 192;
    addr[1] = 168;
    addr[2] = 1;
    addr[3] = 1;
    return 0;
  } else {
    return -1;
  }
}

static int get_AAAA_Record(uint8_t addr[16], const char domain_name[])
{
  if (strcmp("foo.bar.com", domain_name) == 0) {
    addr[0] = 0xfe;
    addr[1] = 0x80;
    addr[2] = 0x00;
    addr[3] = 0x00;
    addr[4] = 0x00;
    addr[5] = 0x00;
    addr[6] = 0x00;
    addr[7] = 0x00;
    addr[8] = 0x00;
    addr[9] = 0x00;
    addr[10] = 0x00;
    addr[11] = 0x00;
    addr[12] = 0x00;
    addr[13] = 0x00;
    addr[14] = 0x00;
    addr[15] = 0x01;
    return 0;
  } else {
    return -1;
  }
}

static int get_TXT_Record(char ** addr, const char domain_name[])
{
  if (strcmp("foo.bar.com", domain_name) == 0) {
    *addr = "abcdefg";
    return 0;
  } else {
    return -1;
  }
}

/*
* Debugging functions.
*/

void print_hex(uint8_t *buf, ssize_t len)
{
  printf("%zu bytes:\n", len);
  for (ssize_t i = 0; i < len; ++i)
    printf("%02x ", buf[i]);
  printf("\n");
}

void print_resource_record(struct ResourceRecord *rr)
{
  int i;
  while (rr) {
    printf("  ResourceRecord { name '%s', type %u, class %u, ttl %u, rd_length %u, ",
      rr->name,
      rr->type,
      rr->class,
      rr->ttl,
      rr->rd_length
   );

    union ResourceData *rd = &rr->rd_data;
    switch (rr->type) {
      case A_Resource_RecordType:
        printf("Address Resource Record { address ");

        for(i = 0; i < 4; ++i)
          printf("%s%u", (i ? "." : ""), rd->a_record.addr[i]);

        printf(" }");
        break;
      case AAAA_Resource_RecordType:
        printf("AAAA Resource Record { address ");

        for(i = 0; i < 16; ++i)
          printf("%s%02x", (i ? ":" : ""), rd->aaaa_record.addr[i]);

        printf(" }");
        break;
      case TXT_Resource_RecordType:
        printf("Text Resource Record { txt_data '%s' }",
          rd->txt_record.txt_data
       );
        break;
      default:
        printf("Unknown Resource Record { ??? }");
    }
    printf("}\n");
    rr = rr->next;
  }
}

void print_message(struct Message *msg)
{
  struct Question *q;

  printf("QUERY { ID: %02x", msg->id);
  printf(". FIELDS: [ QR: %u, OpCode: %u ]", msg->qr, msg->opcode);
  printf(", QDcount: %u", msg->qdCount);
  printf(", ANcount: %u", msg->anCount);
  printf(", NScount: %u", msg->nsCount);
  printf(", ARcount: %u,\n", msg->arCount);

  q = msg->questions;
  while (q) {
    printf("  Question { qName '%s', qType %u, qClass %u }\n",
      q->qName,
      q->qType,
      q->qClass
    );
    q = q->next;
  }

  print_resource_record(msg->answers);
  print_resource_record(msg->authorities);
  print_resource_record(msg->additionals);

  printf("}\n");
}


/*
* Basic memory operations.
*/

ssize_t get16bits(const uint8_t **buffer)
{
  uint16_t value;

  rte_memcpy(&value, *buffer, 2);
  *buffer += 2;

  return ntohs(value);
}

void put8bits(uint8_t **buffer, uint8_t value)
{
  rte_memcpy(*buffer, &value, 1);
  *buffer += 1;
}

void put16bits(uint8_t **buffer, uint16_t value)
{
  value = htons(value);
  rte_memcpy(*buffer, &value, 2);
  *buffer += 2;
}

void put32bits(uint8_t **buffer, uint32_t value)
{
  value = htonl(value);
  rte_memcpy(*buffer, &value, 4);
  *buffer += 4;
}


/*
* Deconding/Encoding functions.
*/

// 3foo3bar3com0 => foo.bar.com (No full validation is done!)
static char *decode_domain_name(const uint8_t **buf, ssize_t len)
{
  char domain[256];
  for (ssize_t i = 1; i < MIN(256, len); i += 1) {
    uint8_t c = (*buf)[i];
    if (c == 0) {
      domain[i - 1] = 0;
      *buf += i + 1;
      return strdup(domain);
    } else if (c <= 63) {
      domain[i - 1] = '.';
    } else {
      domain[i - 1] = c;
    }
  }

  return NULL;
}

// foo.bar.com => 3foo3bar3com0
static void encode_domain_name(uint8_t **buffer, const char *domain)
{
  uint8_t *buf = *buffer;
  const char *beg = domain;
  const char *pos;
  int len = 0;
  int i = 0;

  while ((pos = strchr(beg, '.'))) {
    len = pos - beg;
    buf[i] = len;
    i += 1;
    rte_memcpy(buf+i, beg, len);
    i += len;

    beg = pos + 1;
  }

  len = strlen(domain) - (beg - domain);

  buf[i] = len;
  i += 1;

  rte_memcpy(buf + i, beg, len);
  i += len;

  buf[i] = 0;
  i += 1;

  *buffer += i;
}


static void decode_header(struct Message *msg, const uint8_t **buffer)
{
  msg->id = get16bits(buffer);

  uint32_t fields = get16bits(buffer);
  msg->qr = (fields & QR_MASK) >> 15;
  msg->opcode = (fields & OPCODE_MASK) >> 11;
  msg->aa = (fields & AA_MASK) >> 10;
  msg->tc = (fields & TC_MASK) >> 9;
  msg->rd = (fields & RD_MASK) >> 8;
  msg->ra = (fields & RA_MASK) >> 7;
  msg->rcode = (fields & RCODE_MASK) >> 0;

  msg->qdCount = get16bits(buffer);
  msg->anCount = get16bits(buffer);
  msg->nsCount = get16bits(buffer);
  msg->arCount = get16bits(buffer);
}

static void encode_header(struct Message *msg, uint8_t **buffer)
{
  put16bits(buffer, msg->id);

  int fields = 0;
  fields |= (msg->qr << 15) & QR_MASK;
  fields |= (msg->rcode << 0) & RCODE_MASK;
  // TODO: insert the rest of the fields
  put16bits(buffer, fields);

  put16bits(buffer, msg->qdCount);
  put16bits(buffer, msg->anCount);
  put16bits(buffer, msg->nsCount);
  put16bits(buffer, msg->arCount);
}

int decode_msg(struct Message *msg, const uint8_t *buffer, int size)
{
  decode_header(msg, &buffer);

  if (msg->anCount != 0 || msg->nsCount != 0) {
    printf("Only questions expected!\n");
    return -1;
  }

  // parse questions
  uint32_t qcount = msg->qdCount;
  for (ssize_t i = 0; i < qcount; ++i) {
    struct Question *q = malloc(sizeof(struct Question));

    q->qName = decode_domain_name(&buffer, size);
    q->qType = get16bits(&buffer);
    q->qClass = get16bits(&buffer);

    if (q->qName == NULL) {
      printf("Failed to decode domain name!\n");
      return -1;
    }

    // prepend question to questions list
    q->next = msg->questions;
    msg->questions = q;
  }

  // We do not expect any resource records to parse here.

  return 0;
}

// For every question in the message add a appropiate resource record
// in either section 'answers', 'authorities' or 'additionals'.
void resolve_query(struct Message *msg)
{
  struct ResourceRecord *beg;
  struct ResourceRecord *rr;
  struct Question *q;
  int rc;

  // leave most values intact for response
  msg->qr = 1; // this is a response
  msg->aa = 1; // this server is authoritative
  msg->ra = 0; // no recursion available
  msg->rcode = Ok_ResponseType;

  // should already be 0
  msg->anCount = 0;
  msg->nsCount = 0;
  msg->arCount = 0;

  // for every question append resource records
  q = msg->questions;
  while (q) {
    rr = malloc(sizeof(struct ResourceRecord));
    memset(rr, 0, sizeof(struct ResourceRecord));

    rr->name = strdup(q->qName);
    rr->type = q->qType;
    rr->class = q->qClass;
    rr->ttl = 60*60; // in seconds; 0 means no caching

    // We only can only answer two question types so far
    // and the answer (resource records) will be all put
    // into the answers list.
    // This behavior is probably non-standard!
    switch (q->qType) {
      case A_Resource_RecordType:
        rr->rd_length = 4;
        rc = get_A_Record(rr->rd_data.a_record.addr, q->qName);
        if (rc < 0)
        {
          free(rr->name);
          free(rr);
          goto next;
        }
        break;
      case AAAA_Resource_RecordType:
        rr->rd_length = 16;
        rc = get_AAAA_Record(rr->rd_data.aaaa_record.addr, q->qName);
        if (rc < 0)
        {
          free(rr->name);
          free(rr);
          goto next;
        }
        break;
      case TXT_Resource_RecordType:
        rc = get_TXT_Record(&(rr->rd_data.txt_record.txt_data), q->qName);
        if (rc < 0) {
          free(rr->name);
          free(rr);
          goto next;
        }
        int txt_data_len = strlen(rr->rd_data.txt_record.txt_data);
        rr->rd_length = txt_data_len + 1;
        rr->rd_data.txt_record.txt_data_len = txt_data_len;
        break;
      /*
      case NS_Resource_RecordType:
      case CNAME_Resource_RecordType:
      case SOA_Resource_RecordType:
      case PTR_Resource_RecordType:
      case MX_Resource_RecordType:
      case TXT_Resource_RecordType:
      */
      default:
        free(rr);
        msg->rcode = NotImplemented_ResponseType;
        printf("Cannot answer question of type %d.\n", q->qType);
        goto next;
    }

    msg->anCount++;

    // prepend resource record to answers list
    beg = msg->answers;
    msg->answers = rr;
    rr->next = beg;

    // jump here to omit question
    next:

    // process next question
    q = q->next;
  }
}

/* @return 0 upon failure, 1 upon success */
static int encode_resource_records(struct ResourceRecord *rr, uint8_t **buffer)
{
  int i;
  while (rr) {
    // Answer questions by attaching resource sections.
    encode_domain_name(buffer, rr->name);
    put16bits(buffer, rr->type);
    put16bits(buffer, rr->class);
    put32bits(buffer, rr->ttl);
    put16bits(buffer, rr->rd_length);

    switch (rr->type) {
      case A_Resource_RecordType:
        for(i = 0; i < 4; ++i)
          put8bits(buffer, rr->rd_data.a_record.addr[i]);
        break;
      case AAAA_Resource_RecordType:
        for(i = 0; i < 16; ++i)
          put8bits(buffer, rr->rd_data.aaaa_record.addr[i]);
        break;
      case TXT_Resource_RecordType:
        put8bits(buffer, rr->rd_data.txt_record.txt_data_len);
        for(i = 0; i < rr->rd_data.txt_record.txt_data_len; i++)
          put8bits(buffer, rr->rd_data.txt_record.txt_data[i]);
        break;
      default:
        fprintf(stderr, "Unknown type %u. => Ignore resource record.\n", rr->type);
      return 1;
    }

    rr = rr->next;
  }

  return 0;
}

/* @return 0 upon failure, 1 upon success */
int encode_msg(struct Message *msg, uint8_t **buffer)
{
  struct Question *q;
  int rc;

  encode_header(msg, buffer);

  q = msg->questions;
  while (q) {
    encode_domain_name(buffer, q->qName);
    put16bits(buffer, q->qType);
    put16bits(buffer, q->qClass);

    q = q->next;
  }

  rc = 0;
  rc |= encode_resource_records(msg->answers, buffer);
  rc |= encode_resource_records(msg->authorities, buffer);
  rc |= encode_resource_records(msg->additionals, buffer);

  return rc;
}

void free_resource_records(struct ResourceRecord *rr)
{
  struct ResourceRecord *next;

  while (rr) {
    free(rr->name);
    next = rr->next;
    free(rr);
    rr = next;
  }
}

void free_questions(struct Question *qq)
{
  struct Question *next;

  while (qq) {
    free(qq->qName);
    next = qq->next;
    free(qq);
    qq = next;
  }
}

#if 0
int main()
{
  // buffer for input/output binary packet
  uint8_t buffer[BUF_SIZE];
  struct sockaddr_in client_addr;
  socklen_t addr_len = sizeof(struct sockaddr_in);
  struct sockaddr_in addr;
  int nbytes, rc;
  int sock;
  int port = 9000;

  struct Message msg;
  memset(&msg, 0, sizeof(struct Message));

  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = INADDR_ANY;
  addr.sin_port = htons(port);

  sock = socket(AF_INET, SOCK_DGRAM, 0);

  rc = bind(sock, (struct sockaddr*) &addr, addr_len);

  if (rc != 0) {
    printf("Could not bind: %s\n", strerror(errno));
    return 1;
  }

  printf("Listening on port %u.\n", port);

  while (1) {
    free_questions(msg.questions);
    free_resource_records(msg.answers);
    free_resource_records(msg.authorities);
    free_resource_records(msg.additionals);
    memset(&msg, 0, sizeof(struct Message));

    /* Receive DNS query */
    nbytes = recvfrom(sock, buffer, sizeof(buffer), 0, (struct sockaddr *) &client_addr, &addr_len);

    if (decode_msg(&msg, buffer, nbytes) != 0) {
      continue;
    }

    /* Print query */
    print_message(&msg);

    /* Resolve query and put the answers into the query message */
    resolve_query(&msg);

    /* Print response */
    print_message(&msg);

    uint8_t *p = buffer;
    if (encode_msg(&msg, &p) != 0) {
      continue;
    }

    /* Send DNS response */
    int buflen = p - buffer;
    sendto(sock, buffer, buflen, 0, (struct sockaddr*) &client_addr, addr_len);
  }
}
#endif
