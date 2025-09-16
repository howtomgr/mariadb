# MariaDB Installation Guide

MariaDB is a free and open-source relational database management system (RDBMS) and a fork of MySQL. Originally developed by Michael "Monty" Widenius, the original developer of MySQL, MariaDB was created to remain free under the GNU GPL after Oracle's acquisition of MySQL. It serves as a FOSS alternative to commercial databases like Oracle Database, Microsoft SQL Server, or IBM Db2, offering enterprise-grade features including Galera clustering, advanced storage engines, and enhanced performance optimizations without licensing costs, with features like ACID compliance, replication, and horizontal scaling.

## Table of Contents
1. [Prerequisites](#prerequisites)
2. [Supported Operating Systems](#supported-operating-systems)
3. [Installation](#installation)
4. [Configuration](#configuration)
5. [Service Management](#service-management)
6. [Troubleshooting](#troubleshooting)
7. [Security Considerations](#security-considerations)
8. [Performance Tuning](#performance-tuning)
9. [Backup and Restore](#backup-and-restore)
10. [System Requirements](#system-requirements)
11. [Support](#support)
12. [Contributing](#contributing)
13. [License](#license)
14. [Acknowledgments](#acknowledgments)
15. [Version History](#version-history)
16. [Appendices](#appendices)

## 1. Prerequisites

- **Hardware Requirements**:
  - CPU: 1 core minimum (4+ cores recommended for production)
  - RAM: 1GB minimum (8GB+ recommended for production)
  - Storage: 5GB minimum (SSD recommended for performance)
  - Network: Stable connectivity for replication and clustering setups
- **Operating System**: 
  - Linux: Any modern distribution with kernel 2.6+
  - macOS: 10.13+ (High Sierra or newer)
  - Windows: Windows Server 2016+ or Windows 10
  - FreeBSD: 11.0+
- **Network Requirements**:
  - Port 3306 (default MariaDB port)
  - Port 4444 (Galera SST - State Snapshot Transfer)
  - Port 4567 (Galera group communication)
  - Port 4568 (Galera IST - Incremental State Transfer)
- **Dependencies**:
  - libc6, libssl, zlib (usually included in distributions)
  - systemd or compatible init system (Linux)
  - Root or administrative access for installation
- **System Access**: root or sudo privileges required


## 2. Supported Operating Systems

This guide supports installation on:
- RHEL 8/9 and derivatives (CentOS Stream, Rocky Linux, AlmaLinux)
- Debian 11/12
- Ubuntu 20.04/22.04/24.04 LTS
- Arch Linux (rolling release)
- Alpine Linux 3.18+
- openSUSE Leap 15.5+ / Tumbleweed
- SUSE Linux Enterprise Server (SLES) 15+
- macOS 12+ (Monterey and later) 
- FreeBSD 13+
- Windows 10/11/Server 2019+ (where applicable)

## 3. Installation

### RHEL/CentOS/Rocky Linux/AlmaLinux

```bash
# Add MariaDB official repository
sudo tee /etc/yum.repos.d/mariadb.repo <<EOF
[mariadb]
name = MariaDB
baseurl = https://mirror.mariadb.org/yum/11.2/rhel/\$releasever/\$basearch
module_hotfixes = 1
gpgkey = https://mirror.mariadb.org/yum/RPM-GPG-KEY-MariaDB
gpgcheck = 1
enabled = 1
EOF

# Import MariaDB GPG key
sudo rpm --import https://mirror.mariadb.org/yum/RPM-GPG-KEY-MariaDB

# Install MariaDB server
sudo yum install -y MariaDB-server MariaDB-client MariaDB-backup

# Enable and start service
sudo systemctl enable --now mariadb

# Secure installation
sudo mysql_secure_installation

# Configure firewall
sudo firewall-cmd --permanent --add-service=mysql
sudo firewall-cmd --reload
```

### Debian/Ubuntu

```bash
# Update package index
sudo apt update

# Install prerequisite packages
sudo apt install -y software-properties-common dirmngr apt-transport-https

# Add MariaDB signing key
curl -o /tmp/mariadb_release_signing_key.asc 'https://mariadb.org/mariadb_release_signing_key.asc'
sudo mv /tmp/mariadb_release_signing_key.asc /etc/apt/trusted.gpg.d/mariadb_release_signing_key.asc

# Add MariaDB repository
sudo add-apt-repository "deb [arch=amd64] https://mirror.mariadb.org/repo/11.2/ubuntu $(lsb_release -cs) main"

# Update package index
sudo apt update

# Install MariaDB server
sudo apt install -y mariadb-server mariadb-client mariadb-backup

# Enable and start service
sudo systemctl enable --now mariadb

# Secure installation
sudo mysql_secure_installation

# Configure firewall
sudo ufw allow mysql
```

### Arch Linux

```bash
# Install MariaDB from official repositories
sudo pacman -S mariadb

# Initialize database
sudo mysql_install_db --user=mysql --basedir=/usr --datadir=/var/lib/mysql

# Enable and start service
sudo systemctl enable --now mariadb

# Secure installation
sudo mysql_secure_installation

# Configuration location: /etc/my.cnf
```

### Alpine Linux

```bash
# Install MariaDB
apk add --no-cache mariadb mariadb-client mariadb-backup

# Initialize database
mysql_install_db --user=mysql --datadir=/var/lib/mysql

# Create mysql user if not exists
adduser -D -H -s /sbin/nologin mysql

# Set permissions
chown -R mysql:mysql /var/lib/mysql

# Enable and start service
rc-update add mariadb default
rc-service mariadb start

# Secure installation
mysql_secure_installation
```

### openSUSE/SLES

```bash
# openSUSE Leap/Tumbleweed
sudo zypper install -y mariadb mariadb-client mariadb-tools

# For latest version from official repository
sudo zypper addrepo https://mirror.mariadb.org/repo/11.2/sles/15/x86_64 mariadb
sudo zypper refresh
sudo zypper install -y MariaDB-server MariaDB-client

# SLES 15
sudo SUSEConnect -p sle-module-server-applications/15.5/x86_64
sudo zypper install -y mariadb mariadb-client

# Initialize database if needed
sudo mysql_install_db --user=mysql

# Enable and start service
sudo systemctl enable --now mariadb

# Secure installation
sudo mysql_secure_installation

# Configure firewall
sudo firewall-cmd --permanent --add-service=mysql
sudo firewall-cmd --reload
```

### macOS

```bash
# Using Homebrew
brew install mariadb

# Start MariaDB service
brew services start mariadb

# Or run manually
mariadb-safe --datadir=/usr/local/var/mysql

# Secure installation
mysql_secure_installation

# Configuration location: /usr/local/etc/my.cnf
# Alternative: /opt/homebrew/etc/my.cnf (Apple Silicon)
```

### FreeBSD

```bash
# Using pkg
pkg install mariadb106-server mariadb106-client

# Using ports
cd /usr/ports/databases/mariadb106-server
make install clean

# Enable MariaDB
echo 'mysql_enable="YES"' >> /etc/rc.conf

# Initialize database
service mysql-server start

# Secure installation
mysql_secure_installation

# Configuration location: /usr/local/etc/mysql/my.cnf
```

### Windows

```powershell
# Method 1: Using Chocolatey
choco install mariadb

# Method 2: Using Scoop
scoop bucket add main
scoop install mariadb

# Method 3: Manual installation
# Download MariaDB from https://mariadb.org/download/
# Run mariadb-*.msi installer

# Install as Windows service
"C:\Program Files\MariaDB 11.2\bin\mysqld" --install MariaDB
net start MariaDB

# Configuration location: C:\Program Files\MariaDB 11.2\data\my.ini
```

## Initial Configuration

### First-Run Setup

1. **Create mysql user** (if not created by package):
```bash
# Linux systems
sudo useradd -r -d /var/lib/mysql -s /sbin/nologin -c "MariaDB Server" mysql
```

2. **Default configuration locations**:
- RHEL/CentOS/Rocky/AlmaLinux: `/etc/my.cnf`
- Debian/Ubuntu: `/etc/mysql/mariadb.conf.d/50-server.cnf`
- Arch Linux: `/etc/my.cnf`
- Alpine Linux: `/etc/my.cnf.d/mariadb-server.cnf`
- openSUSE/SLES: `/etc/my.cnf`
- macOS: `/usr/local/etc/my.cnf`
- FreeBSD: `/usr/local/etc/mysql/my.cnf`
- Windows: `C:\Program Files\MariaDB 11.2\data\my.ini`

3. **Essential settings to change**:

```ini
# /etc/mysql/mariadb.conf.d/50-server.cnf
[mysqld]
# Basic settings
bind-address = 127.0.0.1
port = 3306
socket = /run/mysqld/mysqld.sock
datadir = /var/lib/mysql

# Security settings
sql_mode = STRICT_TRANS_TABLES,ERROR_FOR_DIVISION_BY_ZERO,NO_AUTO_CREATE_USER,NO_ENGINE_SUBSTITUTION
local_infile = 0
skip_name_resolve = 1

# Character set
character_set_server = utf8mb4
collation_server = utf8mb4_unicode_ci

# Performance settings
max_connections = 200
thread_cache_size = 50
table_open_cache = 2048

# InnoDB settings
innodb_buffer_pool_size = 1G
innodb_log_file_size = 256M
innodb_file_per_table = 1
innodb_flush_log_at_trx_commit = 2

# Logging
log_error = /var/log/mysql/error.log
slow_query_log = 1
slow_query_log_file = /var/log/mysql/slow.log
long_query_time = 2

# Binary logging (for replication)
log_bin = mysql-bin
binlog_format = ROW
expire_logs_days = 7
```

### Testing Initial Setup

```bash
# Check if MariaDB is running
sudo systemctl status mariadb

# Test connection
mariadb -u root -p -e "SELECT VERSION();"

# Check user accounts
mariadb -u root -p -e "SELECT User, Host FROM mysql.user;"

# Test database operations
mariadb -u root -p -e "CREATE DATABASE test_db; DROP DATABASE test_db;"

# Check configuration
mariadb -u root -p -e "SHOW VARIABLES LIKE 'character_set%';"
mariadb -u root -p -e "SHOW VARIABLES LIKE 'collation%';"
```

**WARNING:** Change the default root password immediately and remove anonymous users!

## 5. Service Management

### systemd (RHEL, Debian, Ubuntu, Arch, openSUSE)

```bash
# Enable MariaDB to start on boot
sudo systemctl enable mariadb

# Start MariaDB
sudo systemctl start mariadb

# Stop MariaDB
sudo systemctl stop mariadb

# Restart MariaDB
sudo systemctl restart mariadb

# Reload configuration
sudo systemctl reload mariadb

# Check status
sudo systemctl status mariadb

# View logs
sudo journalctl -u mariadb -f
```

### OpenRC (Alpine Linux)

```bash
# Enable MariaDB to start on boot
rc-update add mariadb default

# Start MariaDB
rc-service mariadb start

# Stop MariaDB
rc-service mariadb stop

# Restart MariaDB
rc-service mariadb restart

# Check status
rc-service mariadb status

# View logs
tail -f /var/log/mysql/error.log
```

### rc.d (FreeBSD)

```bash
# Enable in /etc/rc.conf
echo 'mysql_enable="YES"' >> /etc/rc.conf

# Start MariaDB
service mysql-server start

# Stop MariaDB
service mysql-server stop

# Restart MariaDB
service mysql-server restart

# Check status
service mysql-server status
```

### launchd (macOS)

```bash
# Using Homebrew services
brew services start mariadb
brew services stop mariadb
brew services restart mariadb

# Check status
brew services list | grep mariadb

# Manual control
mariadb-safe --datadir=/usr/local/var/mysql
```

### Windows Service Manager

```powershell
# Start MariaDB service
net start MariaDB

# Stop MariaDB service
net stop MariaDB

# Using PowerShell
Start-Service MariaDB
Stop-Service MariaDB
Restart-Service MariaDB

# Check status
Get-Service MariaDB

# View logs
Get-EventLog -LogName Application -Source MariaDB
```

## Advanced Configuration

### High Availability Configuration

```ini
# Master-Slave Replication Configuration
# Master server configuration
[mysqld]
server-id = 1
log_bin = mysql-bin
binlog_format = ROW
binlog_do_db = production_db

# Slave server configuration
[mysqld]
server-id = 2
relay-log = relay-bin
read_only = 1
```

### Galera Cluster Configuration

```ini
# Galera Cluster settings
[mysqld]
# Galera Provider Configuration
wsrep_on = ON
wsrep_provider = /usr/lib/galera/libgalera_smm.so

# Galera Cluster Configuration
wsrep_cluster_name = "MariaDB_Cluster"
wsrep_cluster_address = "gcomm://node1.example.com,node2.example.com,node3.example.com"

# Galera Synchronization Configuration
wsrep_sst_method = rsync
wsrep_sst_auth = wsrep_sst:wsrep_password

# Galera Node Configuration
wsrep_node_address = "node1.example.com"
wsrep_node_name = "mariadb-node-1"

# Required settings
binlog_format = ROW
default_storage_engine = InnoDB
innodb_autoinc_lock_mode = 2
```

### Advanced Security Settings

```ini
# Security hardening
[mysqld]
# SSL/TLS configuration
ssl_cert = /etc/mysql/ssl/server-cert.pem
ssl_key = /etc/mysql/ssl/server-key.pem
ssl_ca = /etc/mysql/ssl/ca-cert.pem
require_secure_transport = ON
tls_version = TLSv1.2,TLSv1.3

# Authentication
plugin-load-add = server_audit=server_audit.so
server_audit_logging = ON
server_audit_events = 'CONNECT,QUERY,TABLE'

# Connection security
max_user_connections = 100
max_connect_errors = 10

# Disable dangerous functions
local_infile = 0
```

## Reverse Proxy Setup

### nginx Configuration

```nginx
# /etc/nginx/sites-available/mariadb-proxy
upstream mariadb_backend {
    server 127.0.0.1:3306 max_fails=3 fail_timeout=30s;
    server 127.0.0.1:3307 max_fails=3 fail_timeout=30s backup;
}

server {
    listen 3306;
    proxy_pass mariadb_backend;
    proxy_timeout 1s;
    proxy_responses 1;
    error_log /var/log/nginx/mariadb.log;
}
```

### HAProxy Configuration

```haproxy
# /etc/haproxy/haproxy.cfg
frontend mariadb_frontend
    bind *:3306
    mode tcp
    option tcplog
    default_backend mariadb_servers

backend mariadb_servers
    mode tcp
    balance roundrobin
    option mysql-check user haproxy
    server mariadb1 127.0.0.1:3306 check
    server mariadb2 127.0.0.1:3307 check backup
```

### ProxySQL Configuration

```sql
-- ProxySQL configuration for MariaDB load balancing
INSERT INTO mysql_servers(hostgroup_id, hostname, port, weight) VALUES
(0, '127.0.0.1', 3306, 900),
(0, '127.0.0.1', 3307, 100);

INSERT INTO mysql_query_rules(rule_id, active, match_pattern, destination_hostgroup, apply) VALUES
(1, 1, '^SELECT.*', 0, 1),
(2, 1, '^INSERT.*', 0, 1);

LOAD MYSQL SERVERS TO RUNTIME;
LOAD MYSQL QUERY RULES TO RUNTIME;
SAVE MYSQL SERVERS TO DISK;
SAVE MYSQL QUERY RULES TO DISK;
```

## Security Configuration

### SSL/TLS Setup

```bash
# Generate SSL certificates for MariaDB
sudo mkdir -p /etc/mysql/ssl

# Create CA certificate
sudo openssl genrsa 2048 > /etc/mysql/ssl/ca-key.pem
sudo openssl req -new -x509 -nodes -days 3650 -key /etc/mysql/ssl/ca-key.pem -out /etc/mysql/ssl/ca-cert.pem -subj "/C=US/ST=State/L=City/O=Organization/CN=MariaDB-CA"

# Create server certificate
sudo openssl req -newkey rsa:2048 -days 3650 -nodes -keyout /etc/mysql/ssl/server-key.pem -out /etc/mysql/ssl/server-req.pem -subj "/C=US/ST=State/L=City/O=Organization/CN=mariadb.example.com"
sudo openssl rsa -in /etc/mysql/ssl/server-key.pem -out /etc/mysql/ssl/server-key.pem
sudo openssl x509 -req -in /etc/mysql/ssl/server-req.pem -days 3650 -CA /etc/mysql/ssl/ca-cert.pem -CAkey /etc/mysql/ssl/ca-key.pem -set_serial 01 -out /etc/mysql/ssl/server-cert.pem

# Create client certificate
sudo openssl req -newkey rsa:2048 -days 3650 -nodes -keyout /etc/mysql/ssl/client-key.pem -out /etc/mysql/ssl/client-req.pem -subj "/C=US/ST=State/L=City/O=Organization/CN=mariadb-client"
sudo openssl rsa -in /etc/mysql/ssl/client-key.pem -out /etc/mysql/ssl/client-key.pem
sudo openssl x509 -req -in /etc/mysql/ssl/client-req.pem -days 3650 -CA /etc/mysql/ssl/ca-cert.pem -CAkey /etc/mysql/ssl/ca-key.pem -set_serial 01 -out /etc/mysql/ssl/client-cert.pem

# Set permissions
sudo chown -R mysql:mysql /etc/mysql/ssl
sudo chmod 600 /etc/mysql/ssl/*-key.pem
sudo chmod 644 /etc/mysql/ssl/*-cert.pem /etc/mysql/ssl/ca-cert.pem
```

### User Security and Privileges

```sql
-- Create secure users with SSL requirements
CREATE USER 'appuser'@'%' IDENTIFIED BY 'SecurePassword123!' REQUIRE SSL;
GRANT SELECT, INSERT, UPDATE, DELETE ON myapp.* TO 'appuser'@'%';

-- Create backup user
CREATE USER 'backup'@'localhost' IDENTIFIED BY 'BackupPassword123!' REQUIRE SSL;
GRANT SELECT, RELOAD, LOCK TABLES, REPLICATION CLIENT ON *.* TO 'backup'@'localhost';

-- Create monitoring user
CREATE USER 'monitor'@'localhost' IDENTIFIED BY 'MonitorPassword123!';
GRANT PROCESS, REPLICATION CLIENT, SELECT ON *.* TO 'monitor'@'localhost';

-- Set password policies
SET GLOBAL strict_password_validation = ON;

-- Remove dangerous defaults
DELETE FROM mysql.user WHERE User = '';
DELETE FROM mysql.user WHERE User = 'root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');
DROP DATABASE IF EXISTS test;
FLUSH PRIVILEGES;
```

### Firewall Rules

```bash
# UFW (Ubuntu/Debian)
sudo ufw allow from 192.168.1.0/24 to any port 3306
sudo ufw reload

# firewalld (RHEL/CentOS/openSUSE)
sudo firewall-cmd --permanent --new-zone=mariadb
sudo firewall-cmd --permanent --zone=mariadb --add-source=192.168.1.0/24
sudo firewall-cmd --permanent --zone=mariadb --add-port=3306/tcp
sudo firewall-cmd --reload

# iptables
sudo iptables -A INPUT -s 192.168.1.0/24 -p tcp --dport 3306 -j ACCEPT
sudo iptables-save > /etc/iptables/rules.v4

# pf (FreeBSD)
# Add to /etc/pf.conf
pass in on $ext_if proto tcp from 192.168.1.0/24 to any port 3306

# Windows Firewall
New-NetFirewallRule -DisplayName "MariaDB" -Direction Inbound -Protocol TCP -LocalPort 3306 -RemoteAddress 192.168.1.0/24 -Action Allow
```

## Database Setup

### Database Creation and Management

```sql
-- Create application database
CREATE DATABASE myapp CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- Create user with specific privileges
CREATE USER 'appuser'@'%' IDENTIFIED BY 'SecurePassword123!' REQUIRE SSL;
GRANT SELECT, INSERT, UPDATE, DELETE ON myapp.* TO 'appuser'@'%';

-- Create tables with proper character set
USE myapp;
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    email VARCHAR(100) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_username (username),
    INDEX idx_email (email)
) ENGINE=InnoDB CHARACTER SET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Example of partitioned table for large datasets
CREATE TABLE logs (
    id BIGINT AUTO_INCREMENT,
    log_date DATE NOT NULL,
    message TEXT,
    PRIMARY KEY (id, log_date)
) ENGINE=InnoDB
PARTITION BY RANGE (YEAR(log_date)) (
    PARTITION p2023 VALUES LESS THAN (2024),
    PARTITION p2024 VALUES LESS THAN (2025),
    PARTITION p_future VALUES LESS THAN MAXVALUE
);
```

### Database Optimization

```sql
-- Analyze and optimize tables
ANALYZE TABLE myapp.users;
OPTIMIZE TABLE myapp.users;

-- Check table status
SHOW TABLE STATUS FROM myapp;

-- Index optimization
SHOW INDEX FROM myapp.users;
ALTER TABLE myapp.users ADD INDEX idx_created (created_at);

-- View performance schema statistics
SELECT * FROM information_schema.table_statistics 
WHERE table_schema = 'myapp' ORDER BY total_latency DESC;
```

## Performance Optimization

### System Tuning

```bash
# MariaDB-specific kernel parameters
sudo tee -a /etc/sysctl.conf <<EOF
# MariaDB optimizations
vm.swappiness = 1
fs.file-max = 65535
net.core.somaxconn = 32768
net.ipv4.tcp_max_syn_backlog = 8192
net.ipv4.ip_local_port_range = 1024 65535
EOF

sudo sysctl -p

# Increase file descriptor limits
sudo tee -a /etc/security/limits.conf <<EOF
mysql soft nofile 65535
mysql hard nofile 65535
EOF
```

### MariaDB Performance Tuning

```ini
# High-performance MariaDB configuration
[mysqld]
# Memory settings
innodb_buffer_pool_size = 8G  # 70-80% of available RAM
innodb_buffer_pool_instances = 8
innodb_log_file_size = 1G
innodb_log_buffer_size = 64M

# Thread settings
thread_cache_size = 100
table_open_cache = 4096
table_definition_cache = 2048

# Connection settings
max_connections = 500
max_user_connections = 450
interactive_timeout = 3600
wait_timeout = 600

# Query cache
query_cache_type = 1
query_cache_size = 256M

# Temporary tables
tmp_table_size = 128M
max_heap_table_size = 128M

# MyISAM settings (if used)
key_buffer_size = 256M
myisam_sort_buffer_size = 128M

# InnoDB optimization
innodb_flush_log_at_trx_commit = 2
innodb_flush_method = O_DIRECT
innodb_file_per_table = 1
innodb_io_capacity = 2000
innodb_read_io_threads = 8
innodb_write_io_threads = 8
```

### Query Optimization

```sql
-- Enable performance schema
SET GLOBAL performance_schema = ON;

-- Query optimization analysis
SELECT * FROM performance_schema.events_statements_summary_by_digest 
ORDER BY sum_timer_wait DESC LIMIT 10;

-- Index usage analysis
SELECT * FROM performance_schema.table_io_waits_summary_by_index_usage 
WHERE object_schema = 'myapp' ORDER BY sum_timer_wait DESC;

-- Slow query analysis
SELECT * FROM mysql.slow_log ORDER BY start_time DESC LIMIT 10;
```

## Monitoring

### Built-in Monitoring

```sql
-- Performance monitoring queries
SHOW GLOBAL STATUS LIKE 'Threads_connected';
SHOW GLOBAL STATUS LIKE 'Queries';
SHOW GLOBAL STATUS LIKE 'Slow_queries';
SHOW GLOBAL STATUS LIKE 'Innodb_buffer_pool_read_requests';
SHOW GLOBAL STATUS LIKE 'Innodb_buffer_pool_reads';

-- Connection monitoring
SELECT 
    USER,
    HOST,
    DB,
    COMMAND,
    TIME,
    STATE,
    INFO
FROM INFORMATION_SCHEMA.PROCESSLIST
WHERE USER != 'system user'
ORDER BY TIME DESC;

-- Database size monitoring
SELECT 
    table_schema AS 'Database',
    ROUND(SUM(data_length + index_length) / 1024 / 1024, 2) AS 'Size (MB)'
FROM information_schema.tables 
GROUP BY table_schema
ORDER BY SUM(data_length + index_length) DESC;
```

### External Monitoring Setup

```bash
# Install MariaDB Exporter for Prometheus
wget https://github.com/prometheus/mysqld_exporter/releases/download/v0.14.0/mysqld_exporter-0.14.0.linux-amd64.tar.gz
tar xzf mysqld_exporter-*.tar.gz
sudo cp mysqld_exporter /usr/local/bin/

# Create monitoring user
mariadb -u root -p <<EOF
CREATE USER 'exporter'@'localhost' IDENTIFIED BY 'ExporterPassword123!';
GRANT PROCESS, REPLICATION CLIENT, SELECT ON *.* TO 'exporter'@'localhost';
FLUSH PRIVILEGES;
EOF

# Create systemd service
sudo tee /etc/systemd/system/mysqld_exporter.service <<EOF
[Unit]
Description=MariaDB Exporter
After=network.target

[Service]
Type=simple
User=mysql
Environment=DATA_SOURCE_NAME="exporter:ExporterPassword123!@(localhost:3306)/"
ExecStart=/usr/local/bin/mysqld_exporter
Restart=always

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl enable --now mysqld_exporter
```

### Health Check Scripts

```bash
#!/bin/bash
# mariadb-health-check.sh

# Check MariaDB service
if ! systemctl is-active mariadb >/dev/null 2>&1; then
    echo "CRITICAL: MariaDB service is not running"
    exit 2
fi

# Check connectivity
if ! mariadb -e "SELECT 1;" >/dev/null 2>&1; then
    echo "CRITICAL: Cannot connect to MariaDB"
    exit 2
fi

# Check replication (if configured)
SLAVE_STATUS=$(mariadb -e "SHOW SLAVE STATUS\G" 2>/dev/null | grep "Slave_IO_Running:")
if [ -n "$SLAVE_STATUS" ]; then
    IO_RUNNING=$(echo "$SLAVE_STATUS" | awk '{print $2}')
    if [ "$IO_RUNNING" != "Yes" ]; then
        echo "WARNING: Replication IO thread not running"
        exit 1
    fi
fi

# Check connections
CONNECTIONS=$(mariadb -e "SHOW STATUS LIKE 'Threads_connected';" | tail -1 | awk '{print $2}')
MAX_CONNECTIONS=$(mariadb -e "SHOW VARIABLES LIKE 'max_connections';" | tail -1 | awk '{print $2}')
CONNECTION_USAGE=$((CONNECTIONS * 100 / MAX_CONNECTIONS))

if [ $CONNECTION_USAGE -gt 80 ]; then
    echo "WARNING: High connection usage: ${CONNECTION_USAGE}%"
    exit 1
fi

echo "OK: MariaDB is healthy"
exit 0
```

## 9. Backup and Restore

### Backup Procedures

```bash
#!/bin/bash
# mariadb-backup.sh

BACKUP_DIR="/backup/mariadb/$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR"

# Full database backup
mariadb-dump --all-databases \
  --single-transaction \
  --routines \
  --triggers \
  --events \
  --master-data=2 \
  --user=backup \
  --password=BackupPassword123! \
  --ssl-cert=/etc/mysql/ssl/client-cert.pem \
  --ssl-key=/etc/mysql/ssl/client-key.pem \
  --ssl-ca=/etc/mysql/ssl/ca-cert.pem \
  | gzip > "$BACKUP_DIR/full-backup.sql.gz"

# Individual database backup
mariadb-dump --single-transaction \
  --routines \
  --triggers \
  myapp \
  --user=backup \
  --password=BackupPassword123! \
  --ssl-cert=/etc/mysql/ssl/client-cert.pem \
  --ssl-key=/etc/mysql/ssl/client-key.pem \
  --ssl-ca=/etc/mysql/ssl/ca-cert.pem \
  | gzip > "$BACKUP_DIR/myapp-backup.sql.gz"

# Binary log backup
cp /var/lib/mysql/mysql-bin.* "$BACKUP_DIR/" 2>/dev/null || true

# Configuration backup
tar czf "$BACKUP_DIR/mariadb-config.tar.gz" /etc/mysql/

echo "Backup completed: $BACKUP_DIR"
```

### Restore Procedures

```bash
#!/bin/bash
# mariadb-restore.sh

BACKUP_FILE="$1"
if [ -z "$BACKUP_FILE" ]; then
    echo "Usage: $0 <backup-file.sql.gz>"
    exit 1
fi

# Stop applications using the database
echo "Stopping applications..."

# Restore database
echo "Restoring database from $BACKUP_FILE..."
zcat "$BACKUP_FILE" | mariadb -u root -p

# Verify restore
mariadb -u root -p -e "SHOW DATABASES;"

echo "Restore completed"
```

### Point-in-Time Recovery

```bash
#!/bin/bash
# mariadb-pitr.sh

BACKUP_FILE="$1"
RECOVERY_TIME="$2"

if [ -z "$BACKUP_FILE" ] || [ -z "$RECOVERY_TIME" ]; then
    echo "Usage: $0 <backup-file.sql.gz> <recovery-time>"
    echo "Example: $0 backup.sql.gz '2024-01-15 14:30:00'"
    exit 1
fi

# Restore base backup
zcat "$BACKUP_FILE" | mariadb -u root -p

# Apply binary logs up to recovery point
mysqlbinlog --stop-datetime="$RECOVERY_TIME" /var/lib/mysql/mysql-bin.* | mariadb -u root -p

echo "Point-in-time recovery completed to $RECOVERY_TIME"
```

## 6. Troubleshooting

### Common Issues

1. **MariaDB won't start**:
```bash
# Check logs
sudo journalctl -u mariadb -f
sudo tail -f /var/log/mysql/error.log

# Check disk space
df -h /var/lib/mysql

# Check permissions
ls -la /var/lib/mysql

# Test configuration
mariadb --help --verbose
```

2. **Connection issues**:
```bash
# Check if MariaDB is listening
sudo ss -tlnp | grep :3306

# Test local connection
mariadb -u root -p -e "SELECT 1;"

# Check user privileges
mariadb -u root -p -e "SELECT User, Host FROM mysql.user;"

# Check bind address
mariadb -u root -p -e "SHOW VARIABLES LIKE 'bind_address';"
```

3. **Performance issues**:
```bash
# Check slow queries
mariadb -u root -p -e "SHOW GLOBAL STATUS LIKE 'Slow_queries';"

# Analyze table statistics
mariadb -u root -p -e "SHOW TABLE STATUS FROM myapp;"

# Check buffer pool efficiency
mariadb -u root -p -e "SHOW GLOBAL STATUS LIKE 'Innodb_buffer_pool_read%';"
```

### Debug Mode

```bash
# Start MariaDB with debug options
sudo mariadb --debug --user=mysql --console

# Enable general query log
mariadb -u root -p -e "SET GLOBAL general_log = 1;"
mariadb -u root -p -e "SET GLOBAL general_log_file = '/var/log/mysql/general.log';"

# Analyze queries
sudo tail -f /var/log/mysql/general.log
```

## Maintenance

### Update Procedures

```bash
# RHEL/CentOS/Rocky/AlmaLinux
sudo yum check-update MariaDB-server
sudo yum update MariaDB-server

# Debian/Ubuntu
sudo apt update
sudo apt upgrade mariadb-server

# Arch Linux
sudo pacman -Syu mariadb

# Alpine Linux
apk update
apk upgrade mariadb

# openSUSE
sudo zypper update mariadb

# FreeBSD
pkg update
pkg upgrade mariadb106-server

# Always backup before updates
mariadb -u backup -p < backup.sql

# Run mysql_upgrade after major updates
sudo mysql_upgrade -u root -p
sudo systemctl restart mariadb
```

### Maintenance Tasks

```bash
# Weekly maintenance script
#!/bin/bash
# mariadb-maintenance.sh

# Analyze tables
mariadb -u root -p <<EOF
ANALYZE TABLE myapp.users;
ANALYZE TABLE myapp.logs;
EOF

# Optimize tables
mariadb -u root -p <<EOF
OPTIMIZE TABLE myapp.users;
OPTIMIZE TABLE myapp.logs;
EOF

# Purge old binary logs
mariadb -u root -p -e "PURGE BINARY LOGS BEFORE DATE_SUB(NOW(), INTERVAL 7 DAY);"

# Check for corrupted tables
mysqlcheck --all-databases --check -u root -p

echo "MariaDB maintenance completed"
```

### Health Monitoring

```bash
# Create monitoring cron job
echo "*/5 * * * * /usr/local/bin/mariadb-health-check.sh" | sudo crontab -

# Log rotation
sudo tee /etc/logrotate.d/mariadb <<EOF
/var/log/mysql/*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 640 mysql adm
    sharedscripts
    postrotate
        /usr/bin/mysqladmin flush-logs
    endscript
}
EOF
```

## Integration Examples

### Django Integration

```python
# Django settings.py
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.mysql',
        'NAME': 'myapp',
        'USER': 'appuser',
        'PASSWORD': 'SecurePassword123!',
        'HOST': 'localhost',
        'PORT': '3306',
        'OPTIONS': {
            'ssl': {
                'cert': '/etc/mysql/ssl/client-cert.pem',
                'key': '/etc/mysql/ssl/client-key.pem',
                'ca': '/etc/mysql/ssl/ca-cert.pem',
            },
            'charset': 'utf8mb4',
            'init_command': "SET sql_mode='STRICT_TRANS_TABLES'",
        },
    }
}
```

### WordPress Integration

```php
// wp-config.php
define('DB_NAME', 'wordpress');
define('DB_USER', 'wpuser');
define('DB_PASSWORD', 'SecureWpPassword123!');
define('DB_HOST', 'localhost');
define('DB_CHARSET', 'utf8mb4');
define('DB_COLLATE', 'utf8mb4_unicode_ci');

// Enable SSL
define('MYSQL_SSL_CA', '/etc/mysql/ssl/ca-cert.pem');
define('MYSQL_CLIENT_FLAGS', MYSQLI_CLIENT_SSL);
```

### Node.js Integration

```javascript
// Using mysql2 with SSL
const mysql = require('mysql2/promise');

const connection = await mysql.createConnection({
    host: 'localhost',
    user: 'appuser',
    password: 'SecurePassword123!',
    database: 'myapp',
    ssl: {
        ca: fs.readFileSync('/etc/mysql/ssl/ca-cert.pem'),
        cert: fs.readFileSync('/etc/mysql/ssl/client-cert.pem'),
        key: fs.readFileSync('/etc/mysql/ssl/client-key.pem')
    }
});
```

## Additional Resources

- [Official MariaDB Documentation](https://mariadb.org/documentation/)
- [MariaDB Knowledge Base](https://mariadb.com/kb/en/)
- [MariaDB Security Guide](https://mariadb.com/kb/en/securing-mariadb/)
- [Performance Tuning Guide](https://mariadb.com/kb/en/optimization-and-tuning/)
- [Galera Cluster Documentation](https://mariadb.com/kb/en/galera-cluster/)
- [MariaDB Community Forum](https://mariadb.org/community/)
- [MariaDB Planet Blog Aggregator](https://planet.mariadb.org/)
- [MariaDB Foundation](https://mariadb.org/about/)

---

**Note:** This guide is part of the [HowToMgr](https://howtomgr.github.io) collection. Always refer to official documentation for the most up-to-date information.