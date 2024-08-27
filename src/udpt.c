/*==============================================================================
MIT License

Copyright (c) 2024 Trevor Monk

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
==============================================================================*/

/*!
 * @defgroup udpt UDP Template Broadcasting Engine
 * @brief Broadcast a UDP packet from a template
 * @{
 */

/*============================================================================*/
/*!
@file udpt.c

    UDP Templating Engine

    The udpt component is a UDP broadcasting engine which generates a
    data packet derived from a template and broadcasts this over the
    allowed network interfaces periodically or via a trigger.

*/
/*============================================================================*/

/*==============================================================================
        Includes
==============================================================================*/
#define _GNU_SOURCE
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <fcntl.h>
#include <inttypes.h>
#include <search.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <linux/if_link.h>
#include <sys/mman.h>
#include <time.h>
#include <varserver/varserver.h>
#include <varserver/vartemplate.h>
#include <varserver/varfp.h>

/*==============================================================================
        Private definitions
==============================================================================*/

#ifndef INTERFACE_LIST_LEN
/*! length of the interface list string */
#define INTERFACE_LIST_LEN ( 256 )
#endif

#ifndef MAX_UDPT_SIZE
#define MAX_UDPT_SIZE ( 1472 )
#endif

/*! UDP Template Engine state object */
typedef struct _udptState
{
    /*! variable server handle */
    VARSERVER_HANDLE hVarServer;

    /*! verbose variable name */
    char *verboseVarName;

    /*! verbose variable handle */
    VAR_HANDLE hVerbose;

    /*! verbose flag */
    uint16_t verbose;

    /*! trigger variable name */
    char *triggerVarName;

    /*! trigger variable handle */
    VAR_HANDLE hTrigger;

    /*! transmission rate variable name */
    char *txRateVarName;

    /*! transition rate variable */
    VAR_HANDLE hTxRate;

    /* transmission rate (in seconds) */
    uint32_t txrate_s;

    /*! enable/disable variable name */
    char *enableVarName;

    /*! enable/disable variable handle */
    VAR_HANDLE hEnable;

    /*! enable/disable */
    bool enable;

    /*! interface variable name */
    char *interfaceVarName;

    /*! handle to the interface list variable */
    VAR_HANDLE hInterfaceList;

    /*! template filename */
    char *pTemplateFilename;

    /*! interface list length */
    char interfaceList[INTERFACE_LIST_LEN];

    /*! name of the port variable */
    char *portVarName;

    /*! handle to the broadcast port variable */
    VAR_HANDLE hPort;

    /*! UDP broadcast port */
    uint16_t port;

    /*! metrics variable name */
    char *metricsVarName;

    /*! metrics variable handle */
    VAR_HANDLE hMetrics;

    /*! metrics - unused - placeholder only */
    uint16_t metrics;

    /*! Variable Output stream */
    VarFP *pVarFP;

    /*! Variable output file descriptor */
    int varFd;

} UDPTState;

/*! Var Definition object to define a message variable to be created */
typedef struct _varDef
{
    /* name of the variable */
    char *name;

    /*! variable flags to be set */
    uint32_t flags;

    /*! variable type */
    VarType type;

    /*! length variable (used for strings/blobs only) */
    size_t len;

    /*! notification type for the variable */
    NotificationType notifyType;

    /*! pointer to a location to store the variable handle once it is created */
    VAR_HANDLE *pVarHandle;

    /*! pointer to store the variable value */
    void *pVal;

} VarDef;

/*==============================================================================
        Private file scoped variables
==============================================================================*/

/*! Variable Message Manager State */
static UDPTState state;

/*==============================================================================
        Private function declarations
==============================================================================*/

int main(int argc, char **argv);
static int ProcessOptions( int argC, char *argV[], UDPTState *pState );
static void usage( char *cmdname );
static void TerminationHandler( int signum, siginfo_t *info, void *ptr );
static void SetupTerminationHandler( void );
static int SetupVars( UDPTState *pState );
VAR_HANDLE SetupVar( VARSERVER_HANDLE hVarServer,
                     char *name,
                     VarType type,
                     size_t len,
                     uint32_t flags,
                     NotificationType notify );
static int SetupVarFP( UDPTState *pState );
static void RunMessageHandler( UDPTState *pState );
static int ProcessModified( UDPTState *pState, VAR_HANDLE hVar );
static int ProcessTimer( UDPTState *pState );
static int ProcessTemplate( UDPTState *pState );
static int SendOutput( UDPTState *pState );
static int SendUDP( int family,
                    struct sockaddr *pSockAddr,
                    char *pMsg,
                    size_t len );
static int HandlePrintRequest( UDPTState *pState, int32_t id );
static int PrintUDPTInfo( VAR_HANDLE hVar, UDPTState *pState, int fd );
static int DumpStats( UDPTState *pState, int fd );
static void Output( int fd, char *buf, size_t len );

/*==============================================================================
        Private function definitions
==============================================================================*/

/*============================================================================*/
/*  main                                                                      */
/*!
    Main entry point for the UDP Template Engine

    The main function starts the UDP templating engine

    @param[in]
        argc
            number of arguments on the command line
            (including the command itself)

    @param[in]
        argv
            array of pointers to the command line arguments

    @retval 0 - no error
    @retval 1 - an error occurred

==============================================================================*/
int main(int argc, char **argv)
{
    int result = EINVAL;

    /* clear the UDP template engine state object */
    memset( &state, 0, sizeof( state ) );

    /* process the command line options */
    ProcessOptions( argc, argv, &state );

    /* set up the abnormal termination handler */
    SetupTerminationHandler();

    /* open a handle to the variable server */
    state.hVarServer = VARSERVER_Open();
    if( state.hVarServer != NULL )
    {
        result = SetupVarFP( &state );
        if ( result == EOK )
        {
            result = SetupVars( &state );
            if ( result == EOK )
            {
                RunMessageHandler( &state );
            }
        }

        /* close the handle to the variable server */
       if ( VARSERVER_Close( state.hVarServer ) == EOK )
       {
            state.hVarServer = NULL;
       }
    }

    return ( result == EOK ) ? 0 : 1;
}

/*============================================================================*/
/*  usage                                                                     */
/*!
    Display the application usage

    The usage function dumps the application usage message
    to stderr.

    @param[in]
       cmdname
            pointer to the invoked command name

    @return none

==============================================================================*/
static void usage( char *cmdname )
{
    if( cmdname != NULL )
    {
        fprintf( stderr,
                 "usage: %s [-h] [-v verbose var] [-t trigger var] "
                 "[-r rate var] [-f filename var] [-e enable var] "
                 "[-i interface var] [-m metrics var]\n"
                 " [-v] : verbose mode variable\n"
                 " [-t] : trigger variable\n"
                 " [-r] : transmission rate variable\n"
                 " [-f] : template file\n"
                 " [-e] : enable/disable variable\n"
                 " [-i] : interface list variable\n"
                 " [-m] : metrics variable\n"
                 " [-h] : display this help\n",
                 cmdname );
    }
}

/*============================================================================*/
/*  ProcessOptions                                                            */
/*!
    Process the command line options

    The ProcessOptions function processes the command line options and
    populates the UDPTState object

    @param[in]
        argC
            number of arguments
            (including the command itself)

    @param[in]
        argv
            array of pointers to the command line arguments

    @param[in]
        pState
            pointer to the UDPT State object

    @return 0

==============================================================================*/
static int ProcessOptions( int argC, char *argV[], UDPTState *pState )
{
    int c;
    int result = EINVAL;
    const char *options = "hvf:p:i:e:r:t:";

    if( ( pState != NULL ) &&
        ( argV != NULL ) )
    {
        while( ( c = getopt( argC, argV, options ) ) != -1 )
        {
            switch( c )
            {
                case 'v':
                    pState->verboseVarName = strdup(optarg);
                    break;

                case 'h':
                    usage( argV[0] );
                    break;

                case 'f':
                    pState->pTemplateFilename = strdup(optarg);
                    break;

                case 'p':
                    pState->portVarName = strdup(optarg);
                    break;

                case 'i':
                    pState->interfaceVarName = strdup(optarg);
                    break;

                case 'e':
                    pState->enableVarName = strdup(optarg);
                    break;

                case 'r':
                    pState->txRateVarName = strdup(optarg);
                    break;

                case 't':
                    pState->triggerVarName = strdup(optarg);
                    break;

                case 'm':
                    pState->metricsVarName = strdup(optarg);
                    break;

                default:
                    break;
            }
        }
    }

    return 0;
}


/*============================================================================*/
/*  SetupTerminationHandler                                                   */
/*!
    Set up an abnormal termination handler

    The SetupTerminationHandler function registers a termination handler
    function with the kernel in case of an abnormal termination of this
    process.

==============================================================================*/
static void SetupTerminationHandler( void )
{
    static struct sigaction sigact;

    memset( &sigact, 0, sizeof(sigact) );

    sigact.sa_sigaction = TerminationHandler;
    sigact.sa_flags = SA_SIGINFO;

    sigaction( SIGTERM, &sigact, NULL );
    sigaction( SIGINT, &sigact, NULL );
}

/*============================================================================*/
/*  TerminationHandler                                                        */
/*!
    Abnormal termination handler

    The TerminationHandler function will be invoked in case of an abnormal
    termination of this process.  The termination handler closes
    the connection with the variable server and cleans up any open
    resources.

    @param[in]
        signum
            The signal which caused the abnormal termination (unused)

    @param[in]
        info
            pointer to a siginfo_t object (unused)

    @param[in]
        ptr
            signal context information (ucontext_t) (unused)

==============================================================================*/
static void TerminationHandler( int signum, siginfo_t *info, void *ptr )
{
    /* signum, info, and ptr are unused */
    (void)signum;
    (void)info;
    (void)ptr;

    fprintf( stderr, "Abnormal termination of the UDP template generator\n" );

    if ( state.hVarServer != NULL )
    {
        if ( VARSERVER_Close( state.hVarServer ) == EOK )
        {
            state.hVarServer = NULL;
        }
    }

    exit( 1 );
}

/*============================================================================*/
/*  SetupVars                                                                 */
/*!
    Set up the UDP template generator variables

    The SetupVars function creates and configures the UDP template generator
    variables

    @param[in]
        pState
            pointer to the UDPTState object containing the names of the
            variables to set up.

    @retval
        EOK - UDP Template variables successfully set up
        EINVAL - invalid arguments

==============================================================================*/
static int SetupVars( UDPTState *pState )
{
    int result = EINVAL;
    int errcount = 0;
    int i;
    int n;
    VAR_HANDLE *pVarHandle;

    if ( pState != NULL )
    {
        VARSERVER_HANDLE hVarServer = pState->hVarServer;
        VarDef vars[] =
        {
            { pState->verboseVarName,
              VARFLAG_NONE,
              VARTYPE_UINT16,
              0,
              NOTIFY_MODIFIED,
              &(pState->hVerbose ),
              (void *)&(pState->verbose) },

            { pState->triggerVarName,
              VARFLAG_VOLATILE | VARFLAG_TRIGGER,
              VARTYPE_UINT16,
              0,
              NOTIFY_MODIFIED,
              &(pState->hTrigger ),
              NULL },

            { pState->txRateVarName,
              VARFLAG_NONE,
              VARTYPE_UINT32,
              0,
              NOTIFY_MODIFIED,
              &(pState->hTxRate),
              (void *)&(pState->txrate_s) },

            { pState->enableVarName,
              VARFLAG_NONE,
              VARTYPE_UINT16,
              0,
              NOTIFY_MODIFIED,
              &(pState->hEnable),
              (void *)(&pState->enable) },

            { pState->interfaceVarName,
              VARFLAG_NONE,
              VARTYPE_STR,
              INTERFACE_LIST_LEN,
              NOTIFY_MODIFIED,
              &(pState->hInterfaceList),
              (void *)(&pState->interfaceList) },

            { pState->portVarName,
              VARFLAG_NONE,
              VARTYPE_UINT16,
              0,
              NOTIFY_MODIFIED,
              &(pState->hPort),
              (void *)(&pState->port) },

            { pState->metricsVarName,
              VARFLAG_NONE,
              VARTYPE_UINT16,
              0,
              NOTIFY_PRINT,
              &(pState->hMetrics),
              (void *)(&pState->metrics) }
        };

        n = sizeof( vars ) / sizeof( vars[0] );

        for ( i=0 ; i < n ; i++ )
        {
            if ( vars[i].name != NULL )
            {
                /* get a pointer to the location to store the variable handle */
                pVarHandle = vars[i].pVarHandle;
                if ( pVarHandle != NULL )
                {
                    /* create a message variable */
                    *pVarHandle = SetupVar( hVarServer,
                                            vars[i].name,
                                            vars[i].type,
                                            vars[i].len,
                                            vars[i].flags,
                                            vars[i].notifyType );
                    if ( *pVarHandle == VAR_INVALID )
                    {
                        fprintf( stderr,
                                 "Error creating variable: %s\n",
                                 vars[i].name );
                        errcount++;
                    }
                }
            }
        }
    }

    if ( errcount == 0 )
    {
        result = EOK;
    }

    return result;
}

/*============================================================================*/
/*  SetupVar                                                                  */
/*!
    Set up a variable

    The SetupVar function creates a varserver variable to be used to
    interact with the manifest generator.
    The variable may or may not have a notification associated with it.

@param[in]
    hVarServer
        handle to the variable server

@param[in]
    name
        specify the variable name to create

@param[in]
    type
        type of the variable

@param[in]
    len
        length of the variable (strings/blobs only)

@param[in]
    flags
        flags to add to the variable flag set

@param[in]
    notify
        specify the notification type.  Use NOTIFY_NONE if no notification is
        required

==============================================================================*/
VAR_HANDLE SetupVar( VARSERVER_HANDLE hVarServer,
                     char *name,
                     VarType type,
                     size_t len,
                     uint32_t flags,
                     NotificationType notify )
{
    VAR_HANDLE hVar = VAR_INVALID;
    VarInfo info;
    int result;
    size_t l;

    if ( name != NULL )
    {
        l = strlen( name );
        if ( l < sizeof( info.name ) )
        {
            memset( &info, 0, sizeof( VarInfo ) );

            info.flags = flags;
            info.var.type = type;
            info.var.len = len;

            /* set the variable name */
            strcpy( info.name, name );

            /* try to create the variable.  This will fail if the variable
               was already pre-created */
            result = VARSERVER_CreateVar( hVarServer, &info );
            if ( result == EOK )
            {
                hVar = info.hVar;
            }

            if ( hVar == VAR_INVALID )
            {
                /* search for the variable which may have been pre-created */
                hVar = VAR_FindByName( hVarServer, info.name );
            }

            if ( ( hVar != VAR_INVALID ) &&
                    ( notify != NOTIFY_NONE ) )
            {
                /* set up variable notification */
                result = VAR_Notify( hVarServer, hVar, notify );
                if ( result != EOK )
                {
                    fprintf( stderr,
                             "VARMSG: Failed to set up notification for '%s'\n",
                             info.name );
                }
            }
        }
    }

    return hVar;
}

/*============================================================================*/
/*  SetupVarFP                                                                */
/*!
    Set up a variable output stream for rendering variables to text

    The SetupVarFP function sets up a shared memory buffer backed by an
    output stream to allow us to render variables (possibly from other
    processes) into a memory buffer.

    @param[in]
        pState
            pointer to the UDPTState object to initialize

    @retval EOK the Variable Message rendering buffer was created
    @retval EBADF failed to create the memory buffer
    @retval EINVAL invalid arguments

==============================================================================*/
static int SetupVarFP( UDPTState *pState )
{
    int result = EINVAL;
    char varfp_name[64];
    time_t now;
    int n;
    size_t len = sizeof(varfp_name);

    if ( pState != NULL )
    {
        result = EBADF;

        /* generate a temporary name for the VarFP */
        now = time(NULL);
        n = snprintf(varfp_name, sizeof(varfp_name), "udpt_%ld", now );
        if ( ( n > 0 ) && ( (size_t)n < len ) )
        {
            /* open a VarFP object for printing */
            pState->pVarFP = VARFP_Open(varfp_name, MAX_UDPT_SIZE );
            if ( pState->pVarFP != NULL )
            {
                /* get a file descriptor for the memory buffer */
                pState->varFd = VARFP_GetFd( pState->pVarFP );
                if ( pState->varFd != -1 )
                {
                    result = EOK;
                }
            }
        }
    }

    return result;
}

/*============================================================================*/
/*  RunMessageHandler                                                         */
/*!
    Run the message handler loop

    The RunMessageHandler function waits for an external signal
    either from a timer, or from the variable server.

    @param[in]
        pState
            pointer to the UDPTState object

    @retval EOK message handler exited ok
    @retval other error

==============================================================================*/
static void RunMessageHandler( UDPTState *pState )
{
    int sig;
    int sigval;
    int result;
    VAR_HANDLE hVar;

    while( 1 )
    {
        /* wait for a received signal */
        sig = VARSERVER_WaitSignal( &sigval );
        if ( sig == SIG_VAR_TIMER )
        {
            /* process received timer signal */
            result = ProcessTimer( pState );
        }
        else if ( sig == SIG_VAR_MODIFIED )
        {
            hVar = (VAR_HANDLE)sigval;
            result = ProcessModified( pState, hVar );
        }
        else if ( sig == SIG_VAR_PRINT )
        {
            result = HandlePrintRequest( pState, sigval );
        }
    }
}

/*============================================================================*/
/*  ProcessTimer                                                              */
/*!
    Process a received timer tick

    The ProcessTimer function processes the UDP template and
    transmits the broadcast message

    @param[in]
        pState
            pointer to the UDPTState object to process

    @retval EOK Timer handler processed successfully
    @retval EINVAL invalid argument

==============================================================================*/
static int ProcessTimer( UDPTState *pState )
{
    int result = EINVAL;

    if ( pState != NULL )
    {
        result = ProcessTemplate( pState );
    }

    return result;
}

/*============================================================================*/
/*  ProcessModified                                                           */
/*!
    Process a NOTIFY_MODIFIED notification

    The ProcessModified function handles changes to varserver variables

    @param[in]
        pState
            pointer to the UDPTState object

    @param[in]
        hVar
            handle to the modified variable

    @retval EOK Modified handler processed successfully
    @retval EINVAL invalid argument

==============================================================================*/
static int ProcessModified( UDPTState *pState, VAR_HANDLE hVar )
{
    VarObject obj;
    int result = EINVAL;

    if ( pState != NULL )
    {
        result = ENOTSUP;
        if ( hVar == pState->hTrigger )
        {
            result = ProcessTemplate( pState );
        }
        else if ( hVar == pState->hEnable )
        {
            /* get the value of the enable variable */
            result = VAR_Get( pState->hVarServer, hVar, &obj );
            if ( result == EOK )
            {
                pState->enable = ( obj.val.ul == 0 ) ? false : true;
            }
        }
    }

    return result;
}

/*============================================================================*/
/*  ProcessTemplate                                                           */
/*!
    Process a UDP template

    The ProcessTemplate function processes a template and sends the generated
    output as a UDP broadcast on all allowed networks

    @param[in]
        pState
            pointer to the UDPTState object

    @param[in]
        hVar
            handle to the modified variable

    @retval EOK Modified handler processed successfully
    @retval EINVAL invalid argument

==============================================================================*/
static int ProcessTemplate( UDPTState *pState )
{
    int fd;
    int result = EINVAL;

    if ( pState != NULL )
    {
        /* open input template */
        if ( pState->pTemplateFilename != NULL )
        {
            fd = open( pState->pTemplateFilename, O_RDONLY );
            if ( fd != -1 )
            {
                if ( pState->varFd > 0 )
                {
                    if ( lseek( pState->varFd, 0, SEEK_SET) == 0 )
                    {
                        /* generate the output payload */
                        result = TEMPLATE_FileToFile( pState->hVarServer,
                                                    fd,
                                                    pState->varFd );
                        if ( result == EOK )
                        {
                            /* NUL terminate the buffer */
                            Output( pState->varFd, "\0", 1 );

                            /* send out the output */
                            result = SendOutput( pState );
                        }
                        else
                        {
                            fprintf(stderr, "template generation error\n");
                        }
                    }
                    else
                    {
                        fprintf( stderr, "seek error\n");
                        result = EIO;
                    }
                }
                else
                {
                    fprintf( stderr, "invalid output stream\n");
                    result = EBADF;
                }

                close( fd );
            }
            else
            {
                fprintf( stderr, "invalid template input\n");
                result = ENOENT;
            }
        }
        else
        {
            fprintf( stderr, "No template specified\n");
        }
    }

    return result;
}

/*============================================================================*/
/*  HandlePrintRequest                                                        */
/*!
    Handle a varserver print request notification

    The HandlePrintRequest function handles a print request notification
    from the variable server.

    @param[in]
        pState
            pointer to the UDPT State

    @param[in]
        id
            print notification identifier

    @retval EOK print request notification handled successfully
    @retval EINVAL invalid arguments

==============================================================================*/
static int HandlePrintRequest( UDPTState *pState, int32_t id )
{
    int result = EINVAL;
    VAR_HANDLE hVar;
    int fd;

    if ( pState != NULL )
    {
        /* open a print session */
        if ( VAR_OpenPrintSession( pState->hVarServer,
                                   id,
                                   &hVar,
                                   &fd ) == EOK )
        {
            result = ENOENT;

            if ( hVar == pState->hMetrics )
            {
                (void)PrintUDPTInfo( hVar, pState, fd );
            }

            /* Close the print session */
            result = VAR_ClosePrintSession( pState->hVarServer,
                                            id,
                                            fd );
        }
    }

    return result;
}

/*============================================================================*/
/*  PrintUDPTInfo                                                             */
/*!
    Print UDP Templating Engine Information

    The PrintUDPTInfo function prints out the operating statistics information
    for the UDP Templating Engine in response to a varserver print
    request.

    @param[in]
        hVar
            the handle to the variable associated with the data to print

    @param[in]
        pState
            pointer to the UDPTState object containing the info to print

    @param[in]
        fd
            output file descriptor

    @retval EOK print request notification handled successfully
    @retval ENOENT print request is not for the specified manifest
    @retval EINVAL invalid arguments

==============================================================================*/
static int PrintUDPTInfo( VAR_HANDLE hVar, UDPTState *pState, int fd )
{
    int result = EINVAL;

    if ( pState != NULL )
    {
        result = ENOENT;

    }

    return result;
}

/*============================================================================*/
/*  SendOutput                                                                */
/*!
    Send output to UDP broadcast targets

    The SendOutput function sends the UDP payload out to the UDP
    broadcast targets.

    @param[in]
        pState
            pointer to the UDPTState object containing the output to send

    @retval EOK output sent successfully
    @retval EINVAL invalid arguments

==============================================================================*/
static int SendOutput( UDPTState *pState )
{
    int result = EINVAL;
    char *pMsg;
    struct ifaddrs *addrs;
    struct ifaddrs *ifa;
    int family;
    int s;
    char host[NI_MAXHOST];
    int rc;

    if ( pState != NULL )
    {
        /* get a handle to the output buffer */
        pMsg = VARFP_GetData( pState->pVarFP );
        if( pMsg != NULL )
        {
            /* get a list of the output interfaces */
            if ( getifaddrs(&addrs) == 0 )
            {
                ifa = addrs;
                for ( ifa = addrs; ifa != NULL; ifa = ifa->ifa_next )
                {
                    if (ifa->ifa_addr == NULL)
                            continue;

                    family = ifa->ifa_addr->sa_family;

                    if ( ( family == AF_INET ) ||
                         ( family == AF_INET6 ) )
                    {
                        /* send out a UDP message */
                        rc = SendUDP( family,
                                      ifa->ifa_broadaddr,
                                      pMsg,
                                      strlen( pMsg ) );
                    }
                }

                if ( addrs != NULL )
                {
                    freeifaddrs(addrs);
                }
            }
            else
            {
                result = errno;
            }
        }
    }

    return result;
}

/*============================================================================*/
/*  SendUDP                                                                   */
/*!
    Send out a UDP broadcast message

    The SendUDP function sends out a UDP broadcast message on the specified
    broadcast address.

    @param[in]
        family
            interface family

    @param[in]
        pSockAddr
            output inet address

    @param[in]
        pMsg
            pointer to the message to send

    @param[in]
        len
            length of message to send

    @retval EOK output generated ok
    @retval EINVAL invalid arguments
    @retval other error from socket, setsockopt, sendto

==============================================================================*/
static int SendUDP( int family,
                    struct sockaddr *pSockAddr,
                    char *pMsg,
                    size_t len )
{
    int result = EINVAL;
    int fd;
    int broadcast = 1;
    int rc;
    socklen_t addrlen = (family == AF_INET) ? sizeof(struct sockaddr_in)
                                            :  sizeof(struct sockaddr_in6);

    if ( ( pMsg != NULL ) &&
         ( pSockAddr != NULL ) )
    {
        /* open a UDP socket */
        fd = socket( family, SOCK_DGRAM, 0 );
        if ( fd > 0 )
        {
            /* set up socket to broadcast */
            if ( setsockopt( fd,
                             SOL_SOCKET,
                             SO_BROADCAST,
                             &broadcast,
                             sizeof(broadcast)) != -1 )
            {
                /* send out the packet */
                result = sendto( fd, pMsg, len, 0, pSockAddr, addrlen );
            }
            else
            {
                result = errno;
            }

            close( fd );
        }
        else
        {
            result = errno;
        }
    }

    return result;
}

/*============================================================================*/
/*  DumpStats                                                                 */
/*!
    Dump the UDPT statistics to the output file descriptor

    The DumpStats function writes the UDPT statistics
    to the output file descriptor as a JSON object.

    @param[in]
        pState
            pointer to the UDPTState containing the statistics

    @param[in]
        fd
            output file descriptor

    @retval EOK output generated ok
    @retval EINVAL invalid arguments

==============================================================================*/
static int DumpStats( UDPTState *pState, int fd )
{
    int result = EINVAL;
    char timestr[128];
    time_t duration;

    /* write the opening brace */
    Output( fd, "{", 1 );

    if ( pState != NULL )
    {
        result = EOK;
    }

    /* write the closing brace */
    Output( fd, "}", 1 );

    return result;
}

/*============================================================================*/
/*  Output                                                                    */
/*!
    Output a buffer to an output file descriptor

    The Output function wraps the write() system call and performs
    error checking.

    @param[in]
        fd
            output file descriptor

    @param[in]
        buf
            pointer to output buffer

    @param[in]
        len
            number of bytes to write

==============================================================================*/
static void Output( int fd, char *buf, size_t len )
{
    int n;

    if ( ( buf != NULL ) &&
         ( fd != -1 ) &&
         ( len > 0 ) )
    {
        n = write( fd, buf, len );
        if ( (size_t)n != len )
        {
            fprintf( stderr, "write failed\n" );
        }
    }
}

/*! @}
 * end of udpt group */
