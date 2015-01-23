// NSPR include files
#include <nspr/prerror.h>
#include <nspr/prinit.h>

// NSS include files
#include <nss/nss.h>
#include <nss/pk11pub.h>
#include <nss/secmod.h>
#include <nss/ssl.h>
#include <nss/sslproto.h>
#include <netdb.h>
#include <string.h>
#include <nss/sechash.h>

// Private API, no other way to turn a POSIX file descriptor into an
// NSPR handle.

NSPR_API(PRFileDesc*) PR_ImportTCPSocket(int);

void printError(const char *msg) {
  perror(msg);
  exit(1);
}

void _sha_to_ascii(const unsigned char *in, char *out, unsigned int size) {
  
  int i;
  for (i = 0; i < size - 1; i++) {
    
    snprintf(&out[i*3], 4,"%02X:", in[i]);
  }
  snprintf(&out[i*3], 4, "%02X", in[i]);
}

int print_hex(const char *s)
{
  int count=0;
  while(*s){
    printf("%02X", (unsigned int) *s++);
    count++;
  }
  printf("\n");
  return count;
}
int main(int argc, char *argv[])
{

const char* DELIM = "#";

char *host = argv[1];

PR_Init(PR_USER_THREAD, PR_PRIORITY_NORMAL, 0);
NSSInitContext *const ctx =
  NSS_InitContext("sql:/etc/pki/nssdb", "", "", "", NULL,
		    NSS_INIT_READONLY | NSS_INIT_PK11RELOAD);
if (ctx == NULL) {
  const PRErrorCode err = PR_GetError();
  fprintf(stderr, "error: NSPR error code %d: %s\n",
	    err, PR_ErrorToName(err));
  exit(1);
}

// Ciphers to enable.
static const PRUint16 good_ciphers[] = {
  TLS_RSA_WITH_AES_128_CBC_SHA,
  TLS_RSA_WITH_AES_256_CBC_SHA,
  SSL_RSA_WITH_3DES_EDE_CBC_SHA,
  SSL_NULL_WITH_NULL_NULL // sentinel
};

// Check if the current policy allows any strong ciphers.  If it
// doesn't, set the cipher suite policy.  This is not thread-safe
// and has global impact.  Consequently, we only do it if absolutely
// necessary.
int found_good_cipher = 0;
const PRUint16 *p = good_ciphers;
for ( ;*p != SSL_NULL_WITH_NULL_NULL;++p) {
  PRInt32 policy;
  if (SSL_CipherPolicyGet(*p, &policy) != SECSuccess) {
    const PRErrorCode err = PR_GetError();
    fprintf(stderr, "error: policy for cipher %u: error %d: %s\n",
	      (unsigned)*p, err, PR_ErrorToName(err));
    exit(1);
  }
  if (policy == SSL_ALLOWED) {
    fprintf(stderr, "info: found cipher %x\n", (unsigned)*p);
    found_good_cipher = 1;
    break;
  }
}
if (!found_good_cipher) {
  if (NSS_SetDomesticPolicy() != SECSuccess) {
    const PRErrorCode err = PR_GetError();
    fprintf(stderr, "error: NSS_SetDomesticPolicy: error %d: %s\n",
	      err, PR_ErrorToName(err));
    exit(1);
  }
}

// Initialize the trusted certificate store.
char module_name[] = "library=libnssckbi.so name=\"Root Certs\"";
SECMODModule *module = SECMOD_LoadUserModule(module_name, NULL, PR_FALSE);
if (module == NULL || !module->loaded) {
  const PRErrorCode err = PR_GetError();
  fprintf(stderr, "error: NSPR error code %d: %s\n",
	    err, PR_ErrorToName(err));
  exit(1);	
}

struct hostent *server;
struct sockaddr_in serverAddress;
int socketFd = socket(AF_INET, SOCK_STREAM, 0);
if (socketFd < 0)
    printError("ERROR opening socket");
    server = gethostbyname(host); //get server details from IP address
    if (server == NULL) {
      printError("No such host exists\n");
    }
    bzero((char *) &serverAddress, sizeof(serverAddress));
    // Populate the serverAddress structure
    serverAddress.sin_family = AF_INET;
    bcopy((char *) server->h_addr,
    (char *)&serverAddress.sin_addr.s_addr,
    server->h_length);
    serverAddress.sin_port = htons(443);
    if (connect(socketFd, (struct sockaddr *) &serverAddress, //establish a connection to the server
        sizeof(serverAddress)) < 0)
      printError("ERROR connecting");

// Wrap the POSIX file descriptor.  This is an internal NSPR
// function, but it is very unlikely to change.
PRFileDesc* nspr = PR_ImportTCPSocket(socketFd);
socketFd = -1; // Has been taken over by NSPR.

// Add the SSL layer.
{
  PRFileDesc *model = PR_NewTCPSocket();
  PRFileDesc *newfd = SSL_ImportFD(NULL, model);
  if (newfd == NULL) {
    const PRErrorCode err = PR_GetError();
    fprintf(stderr, "error: NSPR error code %d: %s\n",
	      err, PR_ErrorToName(err));
    exit(1);
  }
  model = newfd;
  newfd = NULL;
  if (SSL_OptionSet(model, SSL_ENABLE_SSL2, PR_FALSE) != SECSuccess) {
    const PRErrorCode err = PR_GetError();
    fprintf(stderr, "error: set SSL_ENABLE_SSL2 error %d: %s\n",
	      err, PR_ErrorToName(err));
    exit(1);
  }
  if (SSL_OptionSet(model, SSL_V2_COMPATIBLE_HELLO, PR_FALSE) != SECSuccess) {
    const PRErrorCode err = PR_GetError();
    fprintf(stderr, "error: set SSL_V2_COMPATIBLE_HELLO error %d: %s\n",
	      err, PR_ErrorToName(err));
    exit(1);
  }
  if (SSL_OptionSet(model, SSL_ENABLE_DEFLATE, PR_FALSE) != SECSuccess) {
    const PRErrorCode err = PR_GetError();
    fprintf(stderr, "error: set SSL_ENABLE_DEFLATE error %d: %s\n",
	      err, PR_ErrorToName(err));
    exit(1);
  }
  if (SSL_OptionSet(model, SSL_HANDSHAKE_AS_SERVER, PR_FALSE) != SECSuccess) {
    const PRErrorCode err = PR_GetError();
    fprintf(stderr, "error: set SSL_ENABLE_DEFLATE error %d: %s\n",
        err, PR_ErrorToName(err));
    exit(1);
  }
  if (SSL_OptionSet(model, SSL_HANDSHAKE_AS_CLIENT, PR_FALSE) != SECSuccess) {
    const PRErrorCode err = PR_GetError();
    fprintf(stderr, "error: set SSL_ENABLE_DEFLATE error %d: %s\n",
        err, PR_ErrorToName(err));
    exit(1);
  }
  // Allow overriding invalid certificate.
  /*SSLBadCertHandler bad_certificate=null;
  if (SSL_BadCertHook(model, bad_certificate, (char *)host) != SECSuccess) {
    const PRErrorCode err = PR_GetError();
    fprintf(stderr, "error: SSL_BadCertHook error %d: %s\n",
	      err, PR_ErrorToName(err));
    exit(1);
  }*/

  newfd = SSL_ImportFD(model, nspr);
  if (newfd == NULL) {
    const PRErrorCode err = PR_GetError();
    fprintf(stderr, "error: SSL_ImportFD error %d: %s\n",
	      err, PR_ErrorToName(err));
    exit(1);
  }
  nspr = newfd;
  PR_Close(model);
}

// Perform the handshake.
if (SSL_ResetHandshake(nspr, PR_FALSE) != SECSuccess) {
  const PRErrorCode err = PR_GetError();
  fprintf(stderr, "error: SSL_ResetHandshake error %d: %s\n",
	    err, PR_ErrorToName(err));
  exit(1);
}
if (SSL_SetURL(nspr, host) != SECSuccess) {
  const PRErrorCode err = PR_GetError();
  fprintf(stderr, "error: SSL_SetURL error %d: %s\n",
	    err, PR_ErrorToName(err));
  exit(1);
}
if (SSL_ForceHandshake(nspr) != SECSuccess) {
  const PRErrorCode err = PR_GetError();
  fprintf(stderr, "error: SSL_ForceHandshake error %d: %s\n",
	    err, PR_ErrorToName(err));
  exit(1);
}

//Fetch the certifcate of server and extract fingeprint from it.
 CERTCertificate *cert = SSL_PeerCertificate(nspr);

 HASHContext *hashctx;
 hashctx = HASH_Create(HASH_AlgSHA1);
 HASH_Begin(hashctx);
 HASH_Update(hashctx,cert->derCert.data,cert->derCert.len);
 
 unsigned char hash[SHA1_LENGTH];
 unsigned int hash_len;
 char fingerprint[HASH_LENGTH_MAX + HASH_LENGTH_MAX/2];
 SECItem digest;
 digest.data = hash;
 HASH_End(hashctx,hash, &hash_len,SHA1_LENGTH);
 HASH_Destroy(hashctx);
 int i=0;
    printf("\n");
    for(i; i<20 ; i++) 
    {
       printf("%02x ",(unsigned char)digest.data[i]); 
    }
    printf("\n");
 _sha_to_ascii(hash,fingerprint,hash_len);

char buf[4096];
snprintf(buf, sizeof(buf), "GET / HTTP/1.0\r\nHost: %s\r\n\r\n", host);

PRInt32 ret = PR_Write(nspr, buf, strlen(buf));
if (ret < 0) {
  const PRErrorCode err = PR_GetError();
  fprintf(stderr, "error: PR_Write error %d: %s\n",
	    err, PR_ErrorToName(err));
  exit(1);
}

ret = PR_Read(nspr, buf, sizeof(buf));
if (ret < 0) {
  const PRErrorCode err = PR_GetError();
  fprintf(stderr, "error: PR_Read error %d: %s\n",
	    err, PR_ErrorToName(err));
  exit(1);
}

// Send close_notify alert.
if (PR_Shutdown(nspr, PR_SHUTDOWN_BOTH) != PR_SUCCESS) {
  const PRErrorCode err = PR_GetError();
  fprintf(stderr, "error: PR_Read error %d: %s\n",
	    err, PR_ErrorToName(err));
  exit(1);
}
// Closes the underlying POSIX file descriptor, too.
PR_Close(nspr);
}
