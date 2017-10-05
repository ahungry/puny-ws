/* Copyright (C) 2017 Matthew Carter <m@ahungry.com>
 *
 * Author: Matthew Carter <m@ahungry.com>
 * Maintainer: Matthew Carter <m@ahungry.com>
 * URL: https://github.com/ahungry/puny-ws
 * Version: 0.0.1
 *
 * License:
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * Commentary:
 *
 * Basic websocket implementation, derived from public domain test
 * apps in libwebsockets.h.
 */

#include <libwebsockets.h>
#include <getopt.h>
#include <stdio.h>
#include <string.h>

static struct lws *wsi_basic;
int force_exit = 0;
static unsigned int opts;
const char *my_message = "{\"type\":\"ping\"}";

// Handle tracking JSON structures.
int json_brace_count = 0;
int json_mode = 0;

// Big 'ol buffer to store received data in.
char *rx_buf = NULL;
// char rx_buf[10000];

/* A simple callback block - basically will send ping messages when connecting and
   when it ends up receiving, it will print the output to the user. */
static int callback_protocol_fn (struct lws *wsi, enum lws_callback_reasons reason,
                                 void *user, void *in, size_t len)
{
  char buf[50 + LWS_PRE];
  int deny_deflate = 1;

  switch (reason)
    {
    case LWS_CALLBACK_CLIENT_ESTABLISHED:
      printf ("Connection established.\n");
      lws_callback_on_writable (wsi);

      break;

    case LWS_CALLBACK_CLOSED:
      printf ("Connection closed.\n");
      wsi_basic = NULL; // Deactivate the interaction, so it will re-connect.

      break;

    case LWS_CALLBACK_CLIENT_RECEIVE:
      ((char *) in)[len] = '\0';

      if (json_mode) {
        // Expand our memory
        int rx_buflen = NULL == rx_buf ? 0 : strlen (rx_buf);
        rx_buf = (char *) realloc (rx_buf, sizeof (rx_buf) * (rx_buflen  + len));

        if (NULL == rx_buf)
          {
            fprintf (stderr, "Failed to realloc() memory!");
          }

        // We could copy in batches, but we need to count braces.
        for (uint i = 0; i < len; i++)
          {
            if ('{' == ((char*) in)[i]) json_brace_count++;
            if ('}' == ((char*) in)[i]) json_brace_count--;
          }

        memcpy (rx_buf + rx_buflen, (char *) in, len + 1);

        // If even braces, flush buffer and output.
        if (!json_brace_count) {
          printf ("%s\n\n", rx_buf);
          free (rx_buf);
          rx_buf = NULL;
        }
      } else {
        printf ("%s\n", (char *) in);
      }
      // If we wanted to echo something back...
      // lws_callback_on_writable (wsi);

      break;

    case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
      printf ("Connection error, closing client.\n");

      // In the test-client.c sample, this auto-terminates the wsi
      // Maybe that isn't what you want to do though?
      if (wsi == wsi_basic)
        {
          wsi_basic = NULL;
        }

      break;

      // If this returns a non-zero, it denies the extension basically.
    case LWS_CALLBACK_CLIENT_CONFIRM_EXTENSION_SUPPORTED:
      if ((strcmp((const char *)in, "deflate-stream") == 0) && deny_deflate) {
        printf ("denied deflate-stream extension\n");

        return 1;
      }

      if ((strcmp((const char *)in, "x-webkit-deflate-frame") == 0))
        return 1;

      if ((strcmp((const char *)in, "deflate-frame") == 0))
        return 1;

      return 1;

      break;

      // This is the area where you send your custom messages (you can
      // request it trigger on demand).
    case LWS_CALLBACK_CLIENT_WRITEABLE:
      printf ("Wrote %s of strlen %d\n", my_message, (int) strlen ((char *) my_message));
      strcpy (buf, my_message);
      lws_write (wsi, (unsigned char *) buf, 15, opts | LWS_WRITE_TEXT);

      break;

    default:
      break;
    }

  return 0;
}

/* If a server sends a custom protocol, you can dispatch bassed on this.
   If the server doesn't use protocol, the first element in list will be used. */
static const struct lws_protocols protocols[] = {
  {
    "", // A protocol name or identifier (any unmatched falls in here)
    callback_protocol_fn,
    0,
    20
  },
  { NULL, NULL, 0, 0 }
};

/* Extensions indicate things that can be supported (compression etc.)
   by the underlying client. */
static const struct lws_extension exts[] = {
  {
    "permessage-deflate",
    lws_extension_callback_pm_deflate,
    "permessage-deflate; client_max_window_bits" // client_no_context_takeover
  },
  {
    "deflate-frame",
    lws_extension_callback_pm_deflate,
    "deflate_frame"
  },
  { NULL, NULL, NULL }
};

/* Option block for CLI option flags. */
static struct option options[] = {
  { "help"       ,  no_argument,        NULL, 'h' },
  { "version"    ,  no_argument,        NULL, 'v' },
  { "ssl-unsafe" ,  no_argument,        NULL, 'k' },
  { "ssl"        ,  no_argument,        NULL, 's' },
  { "port"       ,  required_argument,  NULL, 'p' },
  { "path"       ,  required_argument,  NULL, 'u' },
  { "raw"        ,  no_argument,        NULL, 'r' },
  { "json"       ,  no_argument,        NULL, 'j' },
  { NULL         , 0, 0, 0 }
};

int
main (int argc, char *argv[])
{
  // Option setting related
  int n = 0;
  int use_ssl = 0;
  int port = 80;
  char path[1024];

  // Set a default path.
  path[0] = '/';
  path[1] = '\0';

  // lws related
  struct lws_context_creation_info info;
  struct lws_client_connect_info i;
  struct lws_context *context;
  // const char *prot, *p;

  // There are LLL_COUNT (11) bits in log levels
  // Unfortunately, unless lib compiled in DEBUG mode, you can't view any of them!
  int log_level = 0;

  for (int i = 0; i < LLL_COUNT; i++)
    {
      log_level |= 1 << i;
    }

  lws_set_log_level (log_level, NULL);

  // Init memory
  memset (&info, 0, sizeof info);
  memset (&i, 0, sizeof i);

  if (argc < 2) goto usage;
  if (optind >= argc) goto usage;

  while (n >= 0)
    {
      n = getopt_long (argc, argv, "hv", options, NULL);
      if (n < 0) continue;

      switch (n)
        {
        case 'h':
          goto help;

        case 'v':
          goto version;

        case 'k':
          use_ssl = LCCSCF_USE_SSL |
            LCCSCF_ALLOW_SELFSIGNED |
            LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK |
            LCCSCF_ALLOW_EXPIRED;
          break;

        case 's':
          use_ssl = 1;
          break;

        case 'p':
          port = atoi (optarg);
          break;

        case 'u':
          memcpy (path, optarg, strlen (optarg));
          path[strlen (optarg)] = '\0';
          break;

        case 'r':
          json_mode = 0;
          break;

        case 'j':
          json_mode = 1;
          break;

        default:
          goto usage;
        }
    }

  info.port = -1;
  info.protocols = protocols;
  info.gid = -1;
  info.uid = -1;
  info.extensions = exts;
  //info.pt_serv_buf_size = 1024; // Adjust the max bytes sent in a request

  // If you plan to hit wss endpoints, better hope this works and you
  // compiled with openssl support ;)
  info.options |= LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;

  context = lws_create_context (&info);

  if (context == NULL)
    {
      fprintf (stderr, "Creating libwebsocket context failed\n");

      return 1;
    }

  i.context = context;

  i.ssl_connection = use_ssl; // Non-negative to use it
  i.address = argv[optind];
  i.port = port;
  i.host = i.address;
  i.origin = "";
  i.path = path;

  //i.ietf_version_or_minus_one = -1; // Lib says this is deprecated.
  i.protocol = protocols[0].name;
  i.pwsi = &wsi_basic;

  // SSL_set_verify (lws_get_ssl(wsi_basic), SSL_VERIFY_NONE, OpenSSL_client_verify_callback);

  lws_client_connect_via_info (&i);

  while (!force_exit)
    {
      // If you lose connection, try, try again.
      if (NULL == wsi_basic)
        {
          lws_client_connect_via_info (&i);
        }

      // Handle the callback loop I think.
      lws_service (context, 500);

      sleep (0);
    }

  lws_context_destroy (context);

  return 0;

 help:
  printf ("Usage: punyws <server address>[:<port>]\n"
          "Options:\n"
          "  -h, --help                   Display this help.\n"
          "  -v, --version                Print version.\n"
          "  -k, --ssl-unsafe             Use SSL without any trust checks.\n"
          "  -s, --ssl                    Use SSL with trust checks.\n"
          "  -p, --port                   The port to run on.\n"
          "  -u, --path                   The path to request.\n"
          "  -r, --raw                    Output all data as it comes in.\n"
          "  -j, --json                   Break incoming data into JSON receives.\n"
          );

  return 0;

 version:
  printf ("0.0.1\n");

  return 0;

 usage:
  fprintf (stderr, "Usage: punyws <server address>\n");

  return 1;
}
