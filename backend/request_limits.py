"""Bound actual ASGI request bodies, including requests without Content-Length."""
from starlette.responses import JSONResponse


class RequestBodyLimitMiddleware:
    def __init__(self, app, max_bytes=3_000_000):
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope, receive, send):
        if scope['type'] != 'http':
            return await self.app(scope, receive, send)
        lengths = [value for key, value in scope.get('headers', []) if key.lower() == b'content-length']
        if lengths:
            if len(lengths) != 1 or not lengths[0].isdigit():
                return await JSONResponse({'detail': 'Invalid Content-Length'}, status_code=400)(scope, receive, send)
            normalized = lengths[0].lstrip(b'0') or b'0'
            if len(normalized) > len(str(self.max_bytes)) or int(normalized) > self.max_bytes:
                return await self.reject(scope, receive, send)
        # Buffer at most max_bytes before invoking handlers; an oversized stream
        # must not perform partial database writes before it is rejected.
        body = bytearray()
        while True:
            message = await receive()
            if message['type'] == 'http.disconnect':
                return
            body.extend(message.get('body', b''))
            if len(body) > self.max_bytes:
                return await self.reject(scope, receive, send)
            if not message.get('more_body', False):
                break
        consumed = False

        async def replay():
            nonlocal consumed
            if not consumed:
                consumed = True
                return {'type': 'http.request', 'body': bytes(body), 'more_body': False}
            return await receive()

        await self.app(scope, replay, send)

    async def reject(self, scope, receive, send):
        await JSONResponse({'detail': 'Request too large; use chunked evidence upload'}, status_code=413)(scope, receive, send)
