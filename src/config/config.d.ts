// src/config/config.d.ts
declare module 'config/config' {
  export const config: {
    services: {
      http:{ host: string, port: number };
      ssh: { host: string, port: number };
    };
  };
}
