#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
/* 0 ok, <0 error. from: 32 B sender id, app: 16 B app address. */
/* Relay status: url (NULL when offline), fallback = n0's public relay. Register before join/open. */
typedef void (*irp_status_cb)(void *ctx, const char *url, bool fallback);
int32_t irp_status(irp_status_cb cb, void *ctx);
typedef void (*irp_cb)(void *ctx, const uint8_t *from, const uint8_t *app, const uint8_t *data, size_t len);
/* relays: app's default push relays "url#hextoken,url" in preference order, or NULL. */
int32_t irp_join(const char *path, const uint8_t *kek, const char *ticket, const char *relays, irp_cb cb, void *ctx);
int32_t irp_open(const char *path, const uint8_t *kek, const char *relays, irp_cb cb, void *ctx);
int32_t irp_route(bool sandbox, const char *topic, const uint8_t *token, size_t len);
/* One owner process per phone serves the local socket; other apps attach to it for their app ids.
   auth: may uid receive pushes for app (16 B)? attach: out_id gets the shared 32 B device id;
   cb(from == NULL) once means the owner is gone: attach again or become the owner. */
typedef bool (*irp_auth_cb)(void *ctx, uint32_t uid, const uint8_t *app);
int32_t irp_serve(const char *sock, irp_auth_cb auth, void *ctx);
int32_t irp_attach(const char *sock, const uint8_t *apps, size_t n, irp_cb cb, void *ctx, uint8_t *out_id);
void irp_pause(bool p);
void irp_network(uint64_t id);
void irp_kick(void);
int32_t irp_id(uint8_t *out);
int32_t irp_app(const char *name, uint8_t *out);
/* Notification Service Extension: payload length, -1 not ours/duplicate, -2 error. */
intptr_t irp_notification(const char *path, const uint8_t *kek, const char *f, uint8_t *from, uint8_t *app, uint8_t *out, size_t cap);
