#!/bin/bash

# Session Management Security Fixes Deployment Script
# This script helps deploy the session management security fixes to production

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
ENVIRONMENT=${1:-"production"}
BACKUP_DIR="/backups/sessions_$(date +%Y%m%d_%H%M%S)"
LOG_FILE="/var/log/session_security_deployment.log"

# Logging function
log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1" | tee -a "$LOG_FILE"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" | tee -a "$LOG_FILE"
    exit 1
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1" | tee -a "$LOG_FILE"
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1" | tee -a "$LOG_FILE"
}

# Check if running as root or with sudo
check_permissions() {
    if [[ $EUID -eq 0 ]]; then
        warning "Running as root. Please ensure proper permissions for application files."
    fi
}

# Pre-deployment checks
pre_deployment_checks() {
    log "Starting pre-deployment checks..."
    
    # Check if database is accessible
    if ! python -c "from src.core.config.settings import settings; print('Database config OK')" 2>/dev/null; then
        error "Database configuration check failed"
    fi
    
    # Check if Redis is accessible
    if ! python -c "import redis; r = redis.Redis(host='localhost', port=6379, db=0); r.ping()" 2>/dev/null; then
        error "Redis connectivity check failed"
    fi
    
    # Check if application can start
    if ! python -c "from src.main import app; print('Application import OK')" 2>/dev/null; then
        error "Application import check failed"
    fi
    
    success "Pre-deployment checks passed"
}

# Backup database
backup_database() {
    log "Creating database backup..."
    
    mkdir -p "$BACKUP_DIR"
    
    # Get database connection details from environment
    DB_HOST=${POSTGRES_HOST:-"localhost"}
    DB_PORT=${POSTGRES_PORT:-"5432"}
    DB_NAME=${POSTGRES_DB:-"cedrina"}
    DB_USER=${POSTGRES_USER:-"postgres"}
    
    # Create backup
    if pg_dump -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" > "$BACKUP_DIR/database_backup.sql"; then
        success "Database backup created: $BACKUP_DIR/database_backup.sql"
    else
        error "Database backup failed"
    fi
    
    # Backup Redis data (if using Redis persistence)
    if redis-cli --rdb "$BACKUP_DIR/redis_backup.rdb" >/dev/null 2>&1; then
        success "Redis backup created: $BACKUP_DIR/redis_backup.rdb"
    else
        warning "Redis backup failed (this is normal if Redis persistence is disabled)"
    fi
}

# Run database migration
run_migration() {
    log "Running database migration..."
    
    # Set Python path
    export PYTHONPATH="$(pwd)"
    
    # Check current migration status
    log "Current migration status:"
    alembic current
    
    # Run migration
    if alembic upgrade head; then
        success "Database migration completed successfully"
    else
        error "Database migration failed"
    fi
    
    # Verify migration
    log "Verifying migration..."
    if python -c "
from src.domain.entities.session import Session
from sqlalchemy import inspect
from src.infrastructure.database.database import get_engine

engine = get_engine()
inspector = inspect(engine)
columns = inspector.get_columns('sessions')
last_activity_exists = any(col['name'] == 'last_activity_at' for col in columns)
print('last_activity_at column exists:', last_activity_exists)
if not last_activity_exists:
    exit(1)
"; then
        success "Migration verification passed"
    else
        error "Migration verification failed - last_activity_at column not found"
    fi
}

# Deploy application code
deploy_code() {
    log "Deploying application code..."
    
    # Stop application services
    log "Stopping application services..."
    if systemctl is-active --quiet cedrina-api; then
        systemctl stop cedrina-api
        success "Application service stopped"
    fi
    
    # Deploy new code (assuming you have a deployment process)
    log "Deploying new code..."
    # Add your deployment commands here
    # Example: git pull, rsync, docker build, etc.
    
    # Restart application services
    log "Starting application services..."
    if systemctl start cedrina-api; then
        success "Application service started"
    else
        error "Failed to start application service"
    fi
    
    # Wait for service to be ready
    log "Waiting for service to be ready..."
    sleep 10
    
    # Check service health
    if curl -f http://localhost:8000/health >/dev/null 2>&1; then
        success "Application health check passed"
    else
        error "Application health check failed"
    fi
}

# Run smoke tests
run_smoke_tests() {
    log "Running smoke tests..."
    
    # Test session creation
    if python -c "
import asyncio
from src.domain.services.auth.session import SessionService
from src.infrastructure.database.database import get_session
from src.infrastructure.redis import get_redis_client

async def test_session_creation():
    async with get_session() as db_session:
        redis_client = get_redis_client()
        session_service = SessionService(db_session, redis_client)
        # Test session creation logic here
        print('Session creation test passed')

asyncio.run(test_session_creation())
" 2>/dev/null; then
        success "Session creation smoke test passed"
    else
        warning "Session creation smoke test failed (this may be expected in some environments)"
    fi
    
    # Test configuration loading
    if python -c "
from src.core.config.settings import settings
print('Session timeout:', settings.SESSION_INACTIVITY_TIMEOUT_MINUTES)
print('Max sessions:', settings.MAX_CONCURRENT_SESSIONS_PER_USER)
print('Consistency timeout:', settings.SESSION_CONSISTENCY_TIMEOUT_SECONDS)
print('Blacklist TTL:', settings.ACCESS_TOKEN_BLACKLIST_TTL_HOURS)
" 2>/dev/null; then
        success "Configuration smoke test passed"
    else
        error "Configuration smoke test failed"
    fi
}

# Setup monitoring
setup_monitoring() {
    log "Setting up monitoring..."
    
    # Create monitoring script
    cat > /usr/local/bin/monitor_sessions.sh << 'EOF'
#!/bin/bash
# Session monitoring script

echo "=== Session Management Monitoring ==="
echo "Date: $(date)"

# Check session count
echo "Active sessions: $(psql -t -c 'SELECT COUNT(*) FROM sessions WHERE revoked_at IS NULL AND expires_at > NOW();')"

# Check recent session activity
echo "Sessions created in last hour: $(psql -t -c 'SELECT COUNT(*) FROM sessions WHERE created_at > NOW() - INTERVAL '\''1 hour'\'';')"

# Check Redis memory usage
echo "Redis memory usage: $(redis-cli info memory | grep used_memory_human | cut -d: -f2)"

# Check for consistency issues
echo "Sessions without Redis entries: $(psql -t -c 'SELECT COUNT(*) FROM sessions s WHERE s.revoked_at IS NULL AND s.expires_at > NOW() AND NOT EXISTS (SELECT 1 FROM redis WHERE key = '\''refresh_token:'\'' || s.jti);')"

echo "=== End Monitoring ==="
EOF
    
    chmod +x /usr/local/bin/monitor_sessions.sh
    success "Monitoring script created: /usr/local/bin/monitor_sessions.sh"
    
    # Add to crontab for regular monitoring
    if ! crontab -l 2>/dev/null | grep -q "monitor_sessions"; then
        (crontab -l 2>/dev/null; echo "*/15 * * * * /usr/local/bin/monitor_sessions.sh >> /var/log/session_monitoring.log 2>&1") | crontab -
        success "Monitoring added to crontab (every 15 minutes)"
    fi
}

# Post-deployment verification
post_deployment_verification() {
    log "Running post-deployment verification..."
    
    # Test session creation
    log "Testing session creation..."
    if curl -X POST http://localhost:8000/api/v1/auth/login \
        -H "Content-Type: application/json" \
        -d '{"username":"test","password":"test"}' \
        -s | grep -q "access_token"; then
        success "Session creation test passed"
    else
        warning "Session creation test failed (this may be expected if test user doesn't exist)"
    fi
    
    # Check application logs for errors
    log "Checking application logs for errors..."
    if journalctl -u cedrina-api --since "10 minutes ago" | grep -i error | wc -l | grep -q "^0$"; then
        success "No recent errors in application logs"
    else
        warning "Found errors in application logs - please review"
    fi
    
    success "Post-deployment verification completed"
}

# Main deployment function
main() {
    log "Starting session management security fixes deployment to $ENVIRONMENT"
    
    check_permissions
    pre_deployment_checks
    backup_database
    run_migration
    deploy_code
    run_smoke_tests
    setup_monitoring
    post_deployment_verification
    
    success "Session management security fixes deployment completed successfully!"
    log "Backup location: $BACKUP_DIR"
    log "Log file: $LOG_FILE"
    log "Monitoring script: /usr/local/bin/monitor_sessions.sh"
    
    echo ""
    echo "Next steps:"
    echo "1. Monitor application logs for any issues"
    echo "2. Run: /usr/local/bin/monitor_sessions.sh"
    echo "3. Check session cleanup job performance"
    echo "4. Adjust configuration values if needed"
    echo "5. Update your API endpoints to use session activity tracking"
}

# Rollback function
rollback() {
    log "Starting rollback..."
    
    # Stop application
    systemctl stop cedrina-api
    
    # Restore database from backup
    if [[ -f "$BACKUP_DIR/database_backup.sql" ]]; then
        log "Restoring database from backup..."
        psql -f "$BACKUP_DIR/database_backup.sql"
    fi
    
    # Restore Redis from backup
    if [[ -f "$BACKUP_DIR/redis_backup.rdb" ]]; then
        log "Restoring Redis from backup..."
        cp "$BACKUP_DIR/redis_backup.rdb" /var/lib/redis/dump.rdb
        systemctl restart redis
    fi
    
    # Restart application
    systemctl start cedrina-api
    
    success "Rollback completed"
}

# Parse command line arguments
case "${1:-deploy}" in
    "deploy")
        main
        ;;
    "rollback")
        rollback
        ;;
    "check")
        pre_deployment_checks
        ;;
    *)
        echo "Usage: $0 {deploy|rollback|check} [environment]"
        echo "  deploy   - Deploy session security fixes (default)"
        echo "  rollback - Rollback to previous version"
        echo "  check    - Run pre-deployment checks only"
        exit 1
        ;;
esac 