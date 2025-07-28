# Vault Key Versioning API

This document describes the key versioning API endpoints for managing encryption key versions in HashiCorp Vault.

## Overview

The Vault E2EE integration now supports comprehensive key versioning with:
- **Version Creation**: Create new versions of encryption keys
- **Version History**: Track complete audit trail of key changes
- **Rollback Support**: Roll back to previous key versions
- **Soft Delete**: Mark versions as deleted while preserving audit trail
- **Security Features**: Key hash verification and audit logging

## API Endpoints

### Create Key Version

**POST** `/api/v1/vault/keys/{user_id}/versions`

Creates a new version of an encryption key with audit trail.

**Request Body:**
```json
{
  "description": "Monthly key rotation",
  "created_by": "admin@example.com"
}
```

**Response:**
```json
{
  "message": "Key version created successfully",
  "version": {
    "version": 3,
    "created_at": "2024-01-15T10:30:00Z",
    "created_by": "admin@example.com",
    "description": "Monthly key rotation",
    "active": true,
    "key_hash": "sha256:abc123..."
  },
  "timestamp": 1705312200
}
```

### List Key Versions

**GET** `/api/v1/vault/keys/{user_id}/versions`

Returns all versions of an encryption key with metadata (no key data).

**Response:**
```json
{
  "user_id": "user123",
  "versions": [
    {
      "version": 1,
      "created_at": "2024-01-01T00:00:00Z",
      "created_by": "system",
      "description": "Initial key generation",
      "active": false,
      "key_hash": "sha256:def456..."
    },
    {
      "version": 2,
      "created_at": "2024-01-10T12:00:00Z",
      "created_by": "admin@example.com",
      "description": "Security update",
      "active": false,
      "key_hash": "sha256:ghi789..."
    },
    {
      "version": 3,
      "created_at": "2024-01-15T10:30:00Z",
      "created_by": "admin@example.com",
      "description": "Monthly key rotation",
      "active": true,
      "key_hash": "sha256:abc123..."
    }
  ],
  "total": 3,
  "timestamp": 1705312200
}
```

### Rollback Key Version

**POST** `/api/v1/vault/keys/{user_id}/rollback`

Rolls back an encryption key to a previous version.

**Request Body:**
```json
{
  "target_version": 2,
  "rollback_by": "admin@example.com"
}
```

**Response:**
```json
{
  "message": "Key rolled back successfully",
  "user_id": "user123",
  "target_version": 2,
  "rollback_by": "admin@example.com",
  "timestamp": 1705312200
}
```

### Delete Key Version

**DELETE** `/api/v1/vault/keys/{user_id}/versions/{version}`

Soft-deletes a specific version of an encryption key.

**Request Body:**
```json
{
  "deleted_by": "admin@example.com"
}
```

**Response:**
```json
{
  "message": "Key version deleted successfully",
  "user_id": "user123",
  "version": 1,
  "deleted_by": "admin@example.com",
  "timestamp": 1705312200
}
```

**Note**: Cannot delete the currently active version.

### Get Key History

**GET** `/api/v1/vault/keys/{user_id}/history`

Returns the complete version history for an encryption key.

**Response:**
```json
{
  "key_id": "master_key_user123",
  "current_version": 3,
  "total_versions": 3,
  "last_rotation": "2024-01-15T10:30:00Z",
  "rotation_policy": "",
  "versions": [
    {
      "version": 1,
      "created_at": "2024-01-01T00:00:00Z",
      "created_by": "system",
      "description": "[DELETED by admin@example.com] Initial key generation",
      "active": false,
      "key_hash": "sha256:def456..."
    },
    {
      "version": 2,
      "created_at": "2024-01-10T12:00:00Z",
      "created_by": "admin@example.com",
      "description": "Security update",
      "active": false,
      "key_hash": "sha256:ghi789..."
    },
    {
      "version": 3,
      "created_at": "2024-01-15T10:30:00Z",
      "created_by": "admin@example.com",
      "description": "Monthly key rotation",
      "active": true,
      "key_hash": "sha256:abc123..."
    }
  ],
  "timestamp": 1705312200
}
```

## Key Versioning Features

### Version Management
- **Automatic Versioning**: Each new key gets an incremental version number
- **Active Version Tracking**: Only one version is active at a time
- **Version Metadata**: Complete audit trail with timestamps and user information
- **Key Hash Verification**: SHA256 hash for key integrity verification

### Security Features
- **Audit Trail**: Complete history of all key operations
- **Soft Delete**: Deleted versions preserve metadata but remove key data
- **Rollback Protection**: Cannot delete currently active versions
- **Safe Logging**: Only key hashes are logged, never actual key data

### Cache Integration
- **Automatic Cache Updates**: Cache is updated when versions change
- **Cache Invalidation**: Cache is cleared during rollbacks
- **Performance Optimization**: Versioned keys benefit from caching

## Usage Examples

### Create a New Key Version

```bash
curl -X POST http://localhost:8000/api/v1/vault/keys/user123/versions \
  -H "Content-Type: application/json" \
  -d '{
    "description": "Quarterly security rotation",
    "created_by": "security-team@example.com"
  }'
```

### List All Versions

```bash
curl -X GET http://localhost:8000/api/v1/vault/keys/user123/versions
```

### Rollback to Previous Version

```bash
curl -X POST http://localhost:8000/api/v1/vault/keys/user123/rollback \
  -H "Content-Type: application/json" \
  -d '{
    "target_version": 2,
    "rollback_by": "incident-response@example.com"
  }'
```

### Delete Old Version

```bash
curl -X DELETE http://localhost:8000/api/v1/vault/keys/user123/versions/1 \
  -H "Content-Type: application/json" \
  -d '{
    "deleted_by": "cleanup-job@example.com"
  }'
```

### Get Complete History

```bash
curl -X GET http://localhost:8000/api/v1/vault/keys/user123/history
```

## Integration with Existing Features

### E2EE Service Integration
- **Automatic Versioning**: Master keys are automatically versioned
- **Backward Compatibility**: Existing keys work without modification
- **Seamless Operation**: Version management is transparent to encryption operations

### Monitoring Integration
- **Performance Metrics**: Version operations are tracked in monitoring
- **Error Reporting**: Version failures are logged and reported
- **Audit Logging**: All version operations appear in audit logs

### Cache Integration
- **Version-Aware Caching**: Cache keys include version information
- **Automatic Updates**: Cache is updated when versions change
- **Rollback Support**: Cache is cleared during rollbacks

## Security Considerations

### Data Protection
- **Key Isolation**: Each version is stored separately in Vault
- **Access Control**: Version operations respect Vault policies
- **Audit Trail**: Complete record of all version operations

### Operational Security
- **Soft Delete**: Deleted versions preserve audit trail
- **Rollback Verification**: Target versions must exist and be valid
- **Permission Checks**: All operations require proper authentication

## Best Practices

### Key Rotation
1. **Regular Rotation**: Create new versions on a regular schedule
2. **Incident Response**: Create new versions after security incidents
3. **Compliance**: Rotate keys according to compliance requirements
4. **Documentation**: Always include descriptive information

### Version Management
1. **Cleanup Policy**: Regularly delete old, unused versions
2. **Retention Policy**: Keep versions for audit and compliance requirements
3. **Rollback Testing**: Test rollback procedures regularly
4. **Monitoring**: Monitor version creation and usage patterns

### Emergency Procedures
1. **Incident Response**: Use rollback for emergency key compromise
2. **Recovery Planning**: Document version recovery procedures
3. **Access Management**: Ensure proper access to version management APIs
4. **Communication**: Establish procedures for version-related incidents

## Error Handling

### Common Errors

**400 Bad Request**
- Missing required parameters
- Invalid version numbers
- Malformed request body

**404 Not Found**
- User or key not found
- Specified version doesn't exist

**409 Conflict**
- Attempting to delete active version
- Version already exists

**500 Internal Server Error**
- Vault communication failure
- Key generation failure
- Storage operation failure

### Error Response Format

```json
{
  "error": "Failed to create key version",
  "details": "Version 3 already exists for this key"
}
```

## Performance Considerations

### Vault Storage
- **Efficient Storage**: Versions are stored in structured format
- **Query Optimization**: History queries are optimized for performance
- **Batch Operations**: Multiple version operations can be batched

### Caching Strategy
- **Version-Aware**: Cache includes version information
- **Selective Invalidation**: Only affected cache entries are cleared
- **Performance Impact**: Minimal impact on encryption operations

### Monitoring Impact
- **Metrics Collection**: Version operations are included in metrics
- **Low Overhead**: Monitoring adds minimal performance overhead
- **Scalability**: Scales with existing monitoring infrastructure

## Compliance and Audit

### Audit Requirements
- **Complete Trail**: Every version operation is logged
- **Immutable Records**: Audit logs cannot be modified
- **Compliance Ready**: Meets common compliance requirements

### Reporting
- **Version Reports**: Generate reports on key version usage
- **Audit Exports**: Export audit trails for compliance
- **Metrics Dashboard**: Monitor version operations in real-time

The key versioning system provides enterprise-grade key lifecycle management with complete audit trails, rollback capabilities, and seamless integration with existing Vault E2EE infrastructure. 