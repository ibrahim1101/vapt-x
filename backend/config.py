"""Validate deployment settings before connecting to services (never echo secrets)."""
from dataclasses import dataclass
from urllib.parse import urlsplit


@dataclass(frozen=True)
class Settings:
    mongo_url: str
    db_name: str
    frontend_origin: str
    mongo_timeout_ms: int

    @classmethod
    def from_env(cls, env):
        required = ('MONGO_URL', 'DB_NAME', 'JWT_SECRET', 'ADMIN_EMAIL',
                    'ADMIN_PASSWORD', 'FRONTEND_URL', 'INTERNAL_API_URL', 'NMAP_BINARY')
        missing = [key for key in required if not env.get(key, '').strip()]
        if missing:
            raise ValueError('Missing configuration: ' + ', '.join(missing))
        if not env['MONGO_URL'].startswith(('mongodb://', 'mongodb+srv://')):
            raise ValueError('MONGO_URL must be a MongoDB connection URI')
        if any(c in env['DB_NAME'] for c in '/\\ ."$\x00'):
            raise ValueError('DB_NAME contains invalid characters')
        for key, minimum in [('JWT_SECRET', 32), ('ADMIN_PASSWORD', 10)]:
            if len(env[key]) < minimum or env[key].startswith('REPLACE_'):
                raise ValueError(f'{key} must be configured with a strong non-placeholder value')
        if len(env['ADMIN_PASSWORD'].encode('utf-8')) > 72:
            raise ValueError('ADMIN_PASSWORD exceeds the bcrypt 72-byte limit')
        for key in ('FRONTEND_URL', 'INTERNAL_API_URL'):
            try:
                url = urlsplit(env[key])
                port = url.port
            except ValueError:
                raise ValueError(f'{key} is not a valid URL') from None
            if (url.scheme not in ('http', 'https') or not url.hostname or
                    url.username or url.password or url.query or url.fragment or
                    url.path not in ('', '/')):
                raise ValueError(f'{key} must be an HTTP(S) origin without credentials or a path')
        frontend = urlsplit(env['FRONTEND_URL'])
        local_http = env.get('VAPTX_LOCAL_HTTP', '0')
        if local_http not in ('0', '1'):
            raise ValueError('VAPTX_LOCAL_HTTP must be 0 or 1')
        if frontend.scheme == 'http' and not (
                local_http == '1' and frontend.hostname in ('localhost', '127.0.0.1')):
            raise ValueError('HTTP frontend requires explicit loopback-only VAPTX_LOCAL_HTTP=1')
        if local_http == '1' and frontend.hostname not in ('localhost', '127.0.0.1'):
            raise ValueError('VAPTX_LOCAL_HTTP is restricted to loopback frontends')
        try:
            timeout = int(env.get('MONGO_TIMEOUT_MS', '5000'))
        except ValueError:
            raise ValueError('MONGO_TIMEOUT_MS must be an integer') from None
        if not 100 <= timeout <= 30000:
            raise ValueError('MONGO_TIMEOUT_MS must be between 100 and 30000')
        return cls(env['MONGO_URL'], env['DB_NAME'], env['FRONTEND_URL'].rstrip('/'), timeout)
