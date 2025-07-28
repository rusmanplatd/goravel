# Vault Monitoring & Management API

This document describes the monitoring and management API endpoints for the HashiCorp Vault E2EE integration.

## Overview

The Vault integration now includes comprehensive monitoring, performance caching, and management capabilities through dedicated API endpoints.

## API Endpoints

### Health Check

**GET** `/api/v1/vault/health`

Returns the current health status of the Vault connection.

**Response:**
```json
{
  "vault_health": {
    "status": "healthy",
    "last_check": "2024-01-15T10:30:00Z",
    "total_requests": 150,
    "success_rate": "98.67%",
    "avg_response_time": "45ms",
    "token_ttl_seconds": 3600,
    "token_renewable": true,
    "last_error": "",
    "last_error_time": ""
  },
  "timestamp": 1705312200
}
```

**Status Codes:**
- `200 OK`: Vault is healthy
- `503 Service Unavailable`: Vault is unhealthy or sealed

### Metrics

**GET** `/api/v1/vault/metrics`

Returns detailed performance metrics for the Vault connection.

**Response:**
```json
{
  "vault_metrics": {
    "connection": {
      "status": "healthy",
      "last_health_check": "2024-01-15T10:30:00Z",
      "health_check_duration": "12ms"
    },
    "requests": {
      "total": 150,
      "successful": 148,
      "failed": 2,
      "average_response_time": "45ms"
    },
    "token": {
      "ttl_seconds": 3600,
      "renewable": true
    },
    "errors": {
      "last_error": "",
      "last_error_time": "0001-01-01T00:00:00Z"
    }
  },
  "cache_metrics": {
    "total_entries": 25,
    "total_accesses": 340,
    "ttl": "15m0s",
    "oldest_access": "2024-01-15T10:15:00Z",
    "newest_access": "2024-01-15T10:30:00Z"
  },
  "timestamp": 1705312200
}
```

### Integration Status

**GET** `/api/v1/vault/status`

Returns comprehensive status information about the Vault integration.

**Response:**
```json
{
  "integration": "hashicorp_vault",
  "version": "1.0.0",
  "features": [
    "key_management",
    "health_monitoring",
    "performance_caching",
    "metrics_collection",
    "token_renewal"
  ],
  "health": {
    "status": "healthy",
    "last_check": "2024-01-15T10:30:00Z",
    "success_rate": "98.67%"
  },
  "cache": {
    "enabled": true,
    "ttl": "15m0s",
    "stats": {
      "total_entries": 25,
      "total_accesses": 340
    }
  },
  "monitoring": {
    "enabled": true,
    "connection_status": "healthy",
    "is_healthy": true
  }
}
```

### Clear Cache

**POST** `/api/v1/vault/cache/clear`

Clears all cached encryption keys from memory.

**Response:**
```json
{
  "message": "Vault cache cleared successfully",
  "cleared_stats": {
    "total_entries": 25,
    "total_accesses": 340,
    "ttl": "15m0s"
  },
  "timestamp": 1705312200
}
```

### Renew Token

**POST** `/api/v1/vault/token/renew`

Attempts to renew the current Vault authentication token.

**Response (Success):**
```json
{
  "message": "Token renewed successfully",
  "token_info": {
    "ttl_seconds": 7200,
    "renewable": true
  },
  "timestamp": 1705312200
}
```

**Response (Error):**
```json
{
  "error": "Failed to renew token",
  "details": "token is not renewable"
}
```

**Status Codes:**
- `200 OK`: Token renewed successfully
- `400 Bad Request`: Token not renewable or renewal failed
- `503 Service Unavailable`: Vault monitoring not available

## Monitoring Features

### Health Monitoring

- **Continuous Health Checks**: Automatic health checks every 30 seconds
- **Connection Status Tracking**: Monitors healthy, unhealthy, sealed, and standby states
- **Token Expiration Warnings**: Alerts when tokens are expiring soon (< 1 hour)
- **Error Tracking**: Records and reports the last error and timestamp

### Performance Metrics

- **Request Tracking**: Total, successful, and failed request counts
- **Response Time Monitoring**: Average response time tracking
- **Success Rate Calculation**: Percentage of successful requests
- **Health Check Duration**: Time taken for health check operations

### Caching System

- **Automatic Key Caching**: 15-minute TTL for master keys
- **Cache Statistics**: Entry counts, access patterns, and hit rates
- **Automatic Cleanup**: Expired entries removed every 5 minutes
- **Manual Cache Management**: Clear cache via API endpoint

## Security Considerations

### Logging

- **Safe Key Logging**: Only key hashes (first 8 bytes) are logged
- **Audit Trail**: All key operations are logged with timestamps
- **Error Reporting**: Detailed error information for troubleshooting

### Access Control

- **Protected Endpoints**: Consider adding authentication middleware
- **Sensitive Data**: Metrics don't expose actual key values
- **Token Information**: Only TTL and renewable status exposed

## Usage Examples

### Check Vault Health

```bash
curl -X GET http://localhost:8000/api/v1/vault/health
```

### Get Performance Metrics

```bash
curl -X GET http://localhost:8000/api/v1/vault/metrics
```

### Clear Cache

```bash
curl -X POST http://localhost:8000/api/v1/vault/cache/clear
```

### Renew Token

```bash
curl -X POST http://localhost:8000/api/v1/vault/token/renew
```

## Monitoring Integration

### Prometheus Metrics

The metrics can be easily integrated with Prometheus by creating a custom exporter that calls the `/api/v1/vault/metrics` endpoint.

### Health Check Integration

Use the `/api/v1/vault/health` endpoint for:
- Load balancer health checks
- Container orchestration health probes
- Monitoring system alerts

### Dashboard Integration

The metrics provide comprehensive data for creating monitoring dashboards with:
- Connection status indicators
- Request rate and success rate graphs
- Cache performance metrics
- Token expiration alerts

## Troubleshooting

### Common Issues

1. **503 Service Unavailable on /metrics**
   - Vault is in mock mode (test environment)
   - Monitoring not properly initialized

2. **Token Renewal Failures**
   - Token is not renewable
   - Token has expired
   - Insufficient permissions

3. **Cache Performance Issues**
   - High cache miss rate may indicate short TTL
   - Consider adjusting cache TTL based on usage patterns

### Debug Information

Use the `/api/v1/vault/status` endpoint to get comprehensive debug information including:
- Integration version
- Enabled features
- Health status
- Cache configuration
- Monitoring status

## Performance Optimization

### Cache Configuration

The default cache TTL is 15 minutes, but can be adjusted based on:
- Key access patterns
- Security requirements
- Performance needs

### Monitoring Frequency

Health checks run every 30 seconds by default. This can be adjusted for:
- Higher frequency for critical systems
- Lower frequency to reduce Vault load

### Request Optimization

- Keys are cached to reduce Vault API calls
- Health checks use lightweight operations
- Metrics are collected efficiently without impacting performance 