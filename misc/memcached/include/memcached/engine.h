/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
#ifndef MEMCACHED_ENGINE_H
#define MEMCACHED_ENGINE_H

#include <sys/types.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/uio.h>

#include "memcached/protocol_binary.h"
#include "memcached/config_parser.h"
#include "memcached/server_api.h"
#include "memcached/callback.h"

#ifdef __cplusplus
extern "C" {
#endif

/*! \mainpage memcached public API
 *
 * \section intro_sec Introduction
 *
 * The memcached project provides an API for providing engines as well
 * as data definitions for those implementing the protocol in C.  This
 * documentation will explain both to you.
 *
 * \section docs_sec API Documentation
 *
 * Jump right into <a href="modules.html">the modules docs</a> to get started.
 *
 * \example default_engine.c
 */

/**
 * \defgroup Engine Storage Engine API
 * \defgroup Protex Protocol Extension API
 * \defgroup Protocol Binary Protocol Structures
 *
 * \addtogroup Engine
 * @{
 *
 * Most interesting here is to implement engine_interface_v1 for your
 * engine.
 */

#define ENGINE_INTERFACE_VERSION 1

    /**
     * Response codes for engine operations.
     */
    typedef enum {
        ENGINE_SUCCESS     = 0x00, /**< The command executed successfully */
        ENGINE_KEY_ENOENT  = 0x01, /**< The key does not exists */
        ENGINE_KEY_EEXISTS = 0x02, /**< The key already exists */
        ENGINE_ENOMEM      = 0x03, /**< Could not allocate memory */
        ENGINE_NOT_STORED  = 0x04, /**< The item was not stored */
        ENGINE_EINVAL      = 0x05, /**< Invalid arguments */
        ENGINE_ENOTSUP     = 0x06, /**< The engine does not support this */
        ENGINE_EWOULDBLOCK = 0x07, /**< This would cause the engine to block */
        ENGINE_E2BIG       = 0x08, /**< The data is too big for the engine */
        ENGINE_WANT_MORE   = 0x09, /**< The engine want more data if the frontend
                                    * have more data available. */
        ENGINE_DISCONNECT  = 0x0a, /**< Tell the server to disconnect this client */
        ENGINE_FAILED      = 0xff  /**< Generic failue. */
    } ENGINE_ERROR_CODE;

    /**
     * Engine storage operations.
     */
    typedef enum {
        OPERATION_ADD = 1, /**< Store with add semantics */
        OPERATION_SET,     /**< Store with set semantics */
        OPERATION_REPLACE, /**< Store with replace semantics */
        OPERATION_APPEND,  /**< Store with append semantics */
        OPERATION_PREPEND, /**< Store with prepend semantics */
        OPERATION_CAS      /**< Store with set semantics. */
    } ENGINE_STORE_OPERATION;

    /**
     * Data common to any item stored in memcached.
     */
    typedef void item;

    typedef struct {
        uint64_t cas;
        rel_time_t exptime; /**< When the item will expire (relative to process
                             * startup) */
        uint32_t nbytes; /**< The total size of the data (in bytes) */
        uint32_t flags; /**< Flags associated with the item (in network byte order)*/
        uint8_t clsid; /** class id for the object */
        uint16_t nkey; /**< The total length of the key (in bytes) */
        uint16_t nvalue; /** < IN: The number of elements available in value
                          * OUT: the number of elements used in value */
        const void *key;
        struct iovec value[1];
    } item_info;

    typedef struct {
        const char *username;
        const char *config;
    } auth_data_t;

    /**
     * Callback for any function producing stats.
     *
     * @param key the stat's key
     * @param klen length of the key
     * @param val the stat's value in an ascii form (e.g. text form of a number)
     * @param vlen length of the value
     * @param cookie magic callback cookie
     */
    typedef void (*ADD_STAT)(const char *key, const uint16_t klen,
                             const char *val, const uint32_t vlen,
                             const void *cookie);

    /**
     * Callback for adding a response backet
     * @param key The key to put in the response
     * @param keylen The length of the key
     * @param ext The data to put in the extended field in the response
     * @param extlen The number of bytes in the ext field
     * @param body The data body
     * @param bodylen The number of bytes in the body
     * @param datatype This is currently not used and should be set to 0
     * @param status The status code of the return packet (see in protocol_binary
     *               for the legal values)
     * @param cas The cas to put in the return packet
     * @param cookie The cookie provided by the frontend
     * @return true if return message was successfully created, false if an
     *              error occured that prevented the message from being sent
     */
    typedef bool (*ADD_RESPONSE)(const void *key, uint16_t keylen,
                                 const void *ext, uint8_t extlen,
                                 const void *body, uint32_t bodylen,
                                 uint8_t datatype, uint16_t status,
                                 uint64_t cas, const void *cookie);


    /**
     * Abstract interface to an engine.
     */
#ifdef __WIN32__
#undef interface
#endif
    typedef struct engine_interface {
        uint64_t interface; /**< The version number on the engine structure */
    } ENGINE_HANDLE;

    /**
     * Interface to the server.
     */
    typedef struct server_interface_v1 {

        /**
         * Get the auth data for the connection associated with the
         * given cookie.
         *
         * @param cookie The cookie provided by the frontend
         * @param data Pointer to auth_data_t structure for returning the values
         *
         */
        void (*get_auth_data)(const void *cookie, auth_data_t *data);

        /**
         * Store engine-specific session data on the given cookie.
         *
         * The engine interface allows for a single item to be
         * attached to the connection that it can use to track
         * connection-specific data throughout duration of the
         * connection.
         *
         * @param cookie The cookie provided by the frontend
         * @param engine_data pointer to opaque data
         */
        void (*store_engine_specific)(const void *cookie, void *engine_data);

        /**
         * Retrieve engine-specific session data for the given cookie.
         *
         * @param cookie The cookie provided by the frontend
         *
         * @return the data provied by store_engine_specific or NULL
         *         if none was provided
         */
        void *(*get_engine_specific)(const void *cookie);

        /**
         * Retrieve socket file descriptor of the session for the given cookie.
         *
         * @param cookie The cookie provided by the frontend
         *
         * @return the socket file descriptor of the session for the given cookie.
         */
        int (*get_socket_fd)(const void *cookie);

        /**
         * Get the server's version number.
         *
         * @return the server's version number
         */
        const char* (*server_version)(void);

        /**
         * Generate a simple hash value of a piece of data.
         *
         * @param data pointer to data to hash
         * @param size size of the data to generate the hash value of
         * @param seed an extra seed value for the hash function
         * @return hash value of the data.
         */
        uint32_t (*hash)(const void *data, size_t size, uint32_t seed);

        /**
         * Get the relative time for the given time_t value.
         */
        rel_time_t (*realtime)(const time_t exptime);


        /**
         * Let a connection know that IO has completed.
         * @param cookie cookie representing the connection
         * @param status the status for the io operation
         */
        void (*notify_io_complete)(const void *cookie,
                                   ENGINE_ERROR_CODE status);

        /**
         * The current time.
         */
        rel_time_t (*get_current_time)(void);

        /**
         * parser config options
         */
        int (*parse_config)(const char *str, struct config_item items[], FILE *error);

        /**
         * Allocate and deallocate thread-specific stats arrays for engine-maintained separate stats
         */
        void *(*new_stats)(void);
        void (*release_stats)(void*);

        /**
         * Tell the server we've evicted an item.
         */
        void (*count_eviction)(const void *cookie,
                               const void *key,
                               int nkey);

    } SERVER_HANDLE_V1;

    struct item_observer_cb_data {
        const void *key; /* THis isn't going to work from a memory management perspective */
        size_t nkey;
    };

    /* tap flags */
    /* @todo document and reserve the flags.. this is currently just an idea */
    #define TAP_FLAG_SEND_CATCHUP 1
    #define TAP_FLAG_DATA_INCLUDED 2
    #define TAP_FLAG_SEND_ACK 4

    typedef enum { TAP_MUTATION = 1,
                   TAP_DELETION,
                   TAP_FLUSH,
                   TAP_OPAQUE,
                   TAP_ACK,
                   TAP_PAUSE } tap_event_t;

    /**
     * An iterator for the tap stream.
     * The memcached core will keep on calling this function as long as a tap
     * client is connected to the server. Each event returned by the iterator
     * will be encoded in the binary protocol with the appropriate command opcode.
     *
     * If the engine needs to store extra information in the tap stream it should
     * do so by returning the data through the engine_specific pointer. This data
     * should be valid for the core to use (read only) until the next invocation
     * of the iterator, of if the connection is closed.
     *
     * @param handle the engine handle
     * @param cookie identification for the tap stream
     * @param item item to send returned here (check tap_event_t)
     * @param engine_specific engine specific data returned here
     * @param nengine_specific number of bytes of engine specific data
     * @param ttl ttl for this item (Tap stream hops)
     * @param flags tap flags for this object
     * @param seqno sequence number to send
     * @return the tap event to send (or TAP_PAUSE if there isn't any events)
     */
    typedef tap_event_t (*TAP_ITERATOR)(ENGINE_HANDLE* handle,
                                        const void *cookie,
                                        item **item,
                                        void **engine_specific,
                                        uint16_t *nengine_specific,
                                        uint8_t *ttl,
                                        uint16_t *flags,
                                        uint32_t *seqno);

    /**
     * The signature for the "create_instance" function exported from the module.
     *
     * This function should fill out an engine inteface structure according to
     * the interface parameter (Note: it is possible to return a lower version
     * number).
     *
     * @param interface The highest interface level the server supports
     * @param get_server_api function to get the server API from
     * @param Where to store the interface handle
     * @return See description of ENGINE_ERROR_CODE
     */
    typedef ENGINE_ERROR_CODE (*CREATE_INSTANCE)(uint64_t interface,
                                                 GET_SERVER_API get_server_api,
                                                 ENGINE_HANDLE** handle);

    typedef struct {
        /**
         * The identifier of this feature. All values with the most significant bit cleared is reserved
         * for "registered" features.
         */
        uint32_t feature;
        /**
         * A textual description of the feature. (null will print the registered name for the feature
         * (or "Unknown feature"))
         */
        const char *description;
    } feature_info;

    typedef struct {
        /**
         * Textual description of this engine
         */
        const char *description;
        /**
         * The number of features the server provides
         */
        uint32_t num_features;
        /**
         * An array containing all of the features the engine supports
         */
        feature_info features[1];
    } engine_info;

    /**
     * Definition of the first version of the engine interface
     */
    typedef struct engine_interface_v1 {
        /**
         * Engine info.
         */
        struct engine_interface interface;

        /**
         * Get a description of this engine.
         *
         * @param handle the engine handle
         * @return a stringz description of this engine
         */
        const engine_info* (*get_info)(ENGINE_HANDLE* handle);

        /**
         * Initialize an engine instance.
         * This is called *after* creation, but before the engine may be used.
         *
         * @param handle the engine handle
         * @param config_str configuration this engine needs to initialize itself.
         */
        ENGINE_ERROR_CODE (*initialize)(ENGINE_HANDLE* handle,
                                        const char* config_str);

        /**
         * Tear down this engine.
         *
         * @param handle the engine handle
         */
        void (*destroy)(ENGINE_HANDLE* handle);

        /*
         * Item operations.
         */

        /**
         * Allocate an item.
         *
         * @param handle the engine handle
         * @param cookie The cookie provided by the frontend
         * @param output variable that will receive the item
         * @param key the item's key
         * @param nkey the length of the key
         * @param nbytes the number of bytes that will make up the
         *        value of this item.
         * @param flags the item's flags
         * @param exptime the maximum lifetime of this item
         *
         * @return ENGINE_SUCCESS if all goes well
         */
        ENGINE_ERROR_CODE (*allocate)(ENGINE_HANDLE* handle,
                                      const void* cookie,
                                      item **item,
                                      const void* key,
                                      const size_t nkey,
                                      const size_t nbytes,
                                      const int flags,
                                      const rel_time_t exptime);

        /**
         * Remove an item.
         *
         * @param handle the engine handle
         * @param cookie The cookie provided by the frontend
         * @param key the key identifying the item to be removed
         * @param nkey the length of the key
         *
         * @return ENGINE_SUCCESS if all goes well
         */
        ENGINE_ERROR_CODE (*remove)(ENGINE_HANDLE* handle,
                                    const void* cookie,
                                    const void* key,
                                    const size_t nkey,
                                    uint64_t cas);

        /**
         * Indicate that a caller who received an item no longer needs
         * it.
         *
         * @param handle the engine handle
         * @param cookie The cookie provided by the frontend
         * @param item the item to be released
         */
        void (*release)(ENGINE_HANDLE* handle, const
                        void *cookie,
                        item* item);

        /**
         * Retrieve an item.
         *
         * @param handle the engine handle
         * @param cookie The cookie provided by the frontend
         * @param item output variable that will receive the located item
         * @param key the key to look up
         * @param nkey the length of the key
         *
         * @return ENGINE_SUCCESS if all goes well
         */
        ENGINE_ERROR_CODE (*get)(ENGINE_HANDLE* handle,
                                 const void* cookie,
                                 item** item,
                                 const void* key,
                                 const int nkey);

        /**
         * Store an item.
         *
         * @param handle the engine handle
         * @param cookie The cookie provided by the frontend
         * @param item the item to store
         * @param cas the CAS value for conditional sets
         * @param operation the type of store operation to perform.
         *
         * @return ENGINE_SUCCESS if all goes well
         */
        ENGINE_ERROR_CODE (*store)(ENGINE_HANDLE* handle,
                                   const void *cookie,
                                   item* item,
                                   uint64_t *cas,
                                   ENGINE_STORE_OPERATION operation);

        /**
         * Perform an increment or decrement operation on an item.
         *
         * @param handle the engine handle
         * @param cookie The cookie provided by the frontend
         * @param key the key to look up
         * @param nkey the length of the key
         * @param increment if true, increment the value, else decrement
         * @param create if true, create the item if it's missing
         * @param delta the amount to increment or decrement.
         * @param initial when creating, specifies the initial value
         * @param exptime when creating, specifies the expiration time
         * @param cas output CAS value
         * @param result output arithmetic value
         *
         * @return ENGINE_SUCCESS if all goes well
         */
        ENGINE_ERROR_CODE (*arithmetic)(ENGINE_HANDLE* handle,
                                        const void* cookie,
                                        const void* key,
                                        const int nkey,
                                        const bool increment,
                                        const bool create,
                                        const uint64_t delta,
                                        const uint64_t initial,
                                        const rel_time_t exptime,
                                        uint64_t *cas,
                                        uint64_t *result);

        /**
         * Flush the cache.
         *
         * @param handle the engine handle
         * @param cookie The cookie provided by the frontend
         * @param when time at which the flush should take effect
         *
         * @return ENGINE_SUCCESS if all goes well
         */
        ENGINE_ERROR_CODE (*flush)(ENGINE_HANDLE* handle,
                                   const void* cookie, time_t when);

        /*
         * Statistics
         */

        /**
         * Get statistics from the engine.
         *
         * @param handle the engine handle
         * @param cookie The cookie provided by the frontend
         * @param stat_key optional argument to stats
         * @param nkey the length of the stat_key
         * @param add_stat callback to feed results to the output
         *
         * @return ENGINE_SUCCESS if all goes well
         */
        ENGINE_ERROR_CODE (*get_stats)(ENGINE_HANDLE* handle,
                                       const void* cookie,
                                       const char* stat_key,
                                       int nkey,
                                       ADD_STAT add_stat);

        /**
         * Reset the stats.
         *
         * @param handle the engine handle
         * @param cookie The cookie provided by the frontend
         */
        void (*reset_stats)(ENGINE_HANDLE* handle, const void *cookie);

        /**
         * Get an array of per-thread stats. Set to NULL if you don't need it.
         */
        void *(*get_stats_struct)(ENGINE_HANDLE* handle,
                                  const void* cookie);

        /**
         * Aggregate stats among all per-connection stats. Set to NULL if you don't need it.
         */
        ENGINE_ERROR_CODE (*aggregate_stats)(ENGINE_HANDLE* handle,
                                             const void* cookie,
                                             void (*callback)(void*, void*),
                                             void*);


        /**
         * Any unknown command will be considered engine specific.
         *
         * @param handle the engine handle
         * @param cookie The cookie provided by the frontend
         * @param request pointer to request header to be filled in
         * @param response function to transmit data
         *
         * @return ENGINE_SUCCESS if all goes well
         */
        ENGINE_ERROR_CODE (*unknown_command)(ENGINE_HANDLE* handle,
                                             const void* cookie,
                                             protocol_binary_request_header *request,
                                             ADD_RESPONSE response);

        /* TAP operations */

        /**
         * Callback for all incoming TAP messages. It is up to the engine
         * to determine what to do with the event. The core will create and send
         * a TAP_ACK message if the flag section contains TAP_FLAG_SEND_ACK with
         * the status byte mapped from the return code.
         *
         * @param handle the engine handle
         * @param cookie identification for the tap stream
         * @param engine_specific pointer to engine specific data (received)
         * @param nengine_specific number of bytes of engine specific data
         * @param ttl ttl for this item (Tap stream hops)
         * @param tap_flags tap flags for this object
         * @param tap_event the tap event from over the wire
         * @param tap_seqno sequence number for this item
         * @param key the key in the message
         * @param nkey the number of bytes in the key
         * @param flags the flags for the item
         * @param exptime the expiry time for the object
         * @param cas the cas for the item
         * @param data the data for the item
         * @param ndata the number of bytes in the object
         * @return ENGINE_SUCCESS for success
         */
        ENGINE_ERROR_CODE (*tap_notify)(ENGINE_HANDLE* handle,
                                        const void *cookie,
                                        void *engine_specific,
                                        uint16_t nengine,
                                        uint8_t ttl,
                                        uint16_t tap_flags,
                                        tap_event_t tap_event,
                                        uint32_t tap_seqno,
                                        const void *key,
                                        size_t nkey,
                                        uint32_t flags,
                                        uint32_t exptime,
                                        uint64_t cas,
                                        const void *data,
                                        size_t ndata);

        /**
         * Get (or create) a Tap iterator for this connection.
         * @param handle the engine handle
         * @param cookie The connection cookie
         * @param client The "name" of the client
         * @param nclient The number of bytes in the client name
         * @param flags Tap connection flags
         * @param userdata Specific userdata the engine may know how to use
         * @param nuserdata The size of the userdata
         * @return a tap iterator to iterate through the event stream
         */
        TAP_ITERATOR (*get_tap_iterator)(ENGINE_HANDLE* handle, const void* cookie,
                                         const void* client, size_t nclient,
                                         uint32_t flags,
                                         const void* userdata, size_t nuserdata);

        /**
         * Set the CAS id on an item.
         */
        void (*item_set_cas)(ENGINE_HANDLE *handle, item *item, uint64_t cas);

        /**
         * Get information about an item.
         *
         * The loader of the module may need the pointers to the actual data within
         * an item. Instead of having to create multiple functions to get each
         * individual item, this function will get all of them.
         *
         * @param handle the engine that owns the object
         * @param item the item to request information about
         * @param item_info
         * @return true if successful
         */
        bool (*get_item_info)(ENGINE_HANDLE *handle,
                              const item* item,
                              item_info *item_info);
    } ENGINE_HANDLE_V1;

    /**
     * @}
     */

#ifdef __cplusplus
}
#endif

#endif
