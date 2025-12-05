# caddy-ipblock

```caddyfile example
example.com {
    ipblockchecker {
        api_endpoint https://api.example.com/check-ip
        timeout 5s
    }
    
    reverse_proxy localhost:8080
}
```