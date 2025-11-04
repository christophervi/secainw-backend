# SECAINW Backend - Quick Start Guide

![Java](https://img.shields.io/badge/Java-21-orange?style=flat&logo=openjdk)
![Spring Boot](https://img.shields.io/badge/Spring%20Boot-3.4.6-brightgreen?style=flat&logo=spring)
![Maven](https://img.shields.io/badge/Maven-3.6+-blue?style=flat&logo=apache-maven)

A comprehensive cybersecurity analysis platform leveraging multiple AI models for advanced anomaly detection in network traffic and system logs.

---

## Overview

SECAINW (Security AI Network) is a Spring Boot-based backend application that provides REST APIs for AI-powered cybersecurity anomaly detection. The system processes cybersecurity datasets and uses multiple AI models to identify and analyze security threats.

**Key Technologies:**
- Java 21
- Spring Boot 3.4.6
- Spring AI 1.0.0
- Oracle AI Database with Vector Store
- JWT Authentication
- AWS S3 for report storage

---

## Features

✅ **Multi-AI Model Support** - DeepSeek (Reasoner), Anthropic Claude Opus 4.1, OpenAI GPT-5 (High)  
✅ **Dataset Processing** - Network flow and Windows log event analysis  
✅ **Anomaly Detection** - AI-powered event analysis with severity scoring  
✅ **Security** - JWT authentication with Spring Security  
✅ **Report Generation** - PDF reports with AWS S3 storage  
✅ **CVE Enrichment** - Vulnerability data integration  

---

## Prerequisites

### Required Software

1. **Java 21** (Required)
   ```bash
   java -version
   # Must show: version "21.x.x"
   ```
   Download from: https://www.oracle.com/java/technologies/downloads/

2. **Maven 3.8+**
   ```bash
   mvn -version
   ```
   Download from: https://maven.apache.org/

3. **Oracle AI Database** (23ai or higher with Vector Store support)

---

## Quick Start

### 1. Installation

```bash
# Extract and navigate to project
unzip secainw-backend.zip
cd secainw-backend

# Install dependencies
mvn clean install -DskipTests
```

### 2. Configuration

Edit `src/main/resources/application.properties`:

```properties
# Database
spring.datasource.url=jdbc:oracle:thin:@//localhost:1521/FREEPDB1
spring.datasource.username=YOUR_USERNAME
spring.datasource.password=YOUR_PASSWORD

# JWT Security
app.jwt.secret=YOUR_SECURE_SECRET_KEY_256_BITS_MINIMUM
app.jwt.expiration=86400000

# AI Models
spring.ai.deepseek.api-key=YOUR_DEEPSEEK_API_KEY
spring.ai.deepseek.chat.options.model=YOUR_DEEPSEEK_MODEL
spring.ai.anthropic.api-key=YOUR_ANTHROPIC_API_KEY
spring.ai.anthropic.chat.options.model=YOUR_ANTHROPIC_MODEL
spring.ai.openai.api-key=YOUR_OPENAI_API_KEY
spring.ai.openai.chat.options.model=YOUR_OPENAI_MODEL
spring.ai.openai.chat.options.reasoning-effort=high

# AWS S3 (Optional)
aws.s3.bucket-name=your-bucket-name
aws.s3.region=us-west-2
aws.access.key.id=YOUR_AWS_KEY
aws.secret.access.key=YOUR_AWS_SECRET
```

### 3. Run the Application

**Option 1: Using Maven**
```bash
mvn spring-boot:run
```

**Option 2: Using JAR**
```bash
mvn clean package -DskipTests
java -jar target/secainw-backend-0.0.1-SNAPSHOT.jar
```

Application runs on: `http://localhost:8080`

---

## API Endpoints

### Authentication

```bash
# Register User
POST /api/auth/signup
{
  "username": "analyst1",
  "email": "analyst1@example.com",
  "password": "SecurePass123!"
}

# Login
POST /api/auth/login
{
  "username": "analyst1",
  "password": "SecurePass123!"
}
```

### Anomaly Detection

```bash
# Detect Anomaly
POST /api/anomalies/detect
Authorization: Bearer YOUR_JWT_TOKEN
{
  "eventId": "EVT-001",
  "timestamp": "2024-10-31T10:00:00",
  "eventType": "network",
  "sourceIp": "192.168.1.100",
  "destinationIp": "10.0.0.50",
  "destinationPort": 445
}

# Get All Anomalies
GET /api/anomalies
Authorization: Bearer YOUR_JWT_TOKEN

# Get Anomaly by ID
GET /api/anomalies/{id}
Authorization: Bearer YOUR_JWT_TOKEN
```

### Reports

```bash
# Generate PDF Report
GET /api/reports/generate?reportType=summary&aiModel=claude-opus-4.1
Authorization: Bearer YOUR_JWT_TOKEN
```

### Dataset Import

```bash
# Import Network Flow Data
POST /api/lanl/import/netflow
Authorization: Bearer YOUR_JWT_TOKEN

# Import Windows Log Data
POST /api/lanl/import/windows-logs
Authorization: Bearer YOUR_JWT_TOKEN

# Check Import Status
GET /api/lanl/status
Authorization: Bearer YOUR_JWT_TOKEN
```

---

## Project Structure

```
secainw-backend/
├── src/main/java/edu/sjsu/cmpe/secainw/
│   ├── config/              # Configuration (AI, Security)
│   ├── controller/          # REST API endpoints
│   ├── dto/                 # Data Transfer Objects
│   ├── model/               # JPA entities
│   ├── repository/          # Data access layer
│   ├── security/            # JWT & authentication
│   ├── service/             # Business logic
│   └── util/                # Utilities
├── src/main/resources/
│   ├── application.properties
│   └── data/                # Dataset files
└── pom.xml
```

---

## Common Issues & Solutions

### Java Version Error
```bash
# Verify Java 21
java -version

# Set JAVA_HOME
export JAVA_HOME=/path/to/jdk-21
export PATH=$JAVA_HOME/bin:$PATH
```

### Port Already in Use
```bash
# Change port in application.properties
server.port=8081

# Or kill process on port 8080
lsof -ti:8080 | xargs kill -9  # Linux/Mac
```

### Database Connection Failed
- Verify Oracle database is running
- Check connection string and credentials
- Ensure database accepts connections
- Check firewall settings

### Out of Memory
```bash
# Increase heap size
java -Xmx4g -Xms2g -jar target/secainw-backend-0.0.1-SNAPSHOT.jar
```

---

## Configuration Details

### Getting API Keys

**DeepSeek:**
- Platform: https://platform.deepseek.com/api_keys
- Documentation: https://api-docs.deepseek.com/

**Anthropic:**
- Console: https://platform.claude.com/settings/keys/
- Documentation: https://docs.claude.com/en/home

**OpenAI:**
- Platform: https://platform.openai.com/api-keys
- Documentation: https://platform.openai.com/docs

**AWS S3:**
- Console: https://console.aws.amazon.com/
- Create S3 bucket and IAM credentials

**NIST NVD (Optional):**
- Request API key: https://nvd.nist.gov/developers/request-an-api-key

### Generate Secure JWT Secret

```bash
# Generate 256-bit secret key
openssl rand -base64 64
```

---

## Development Commands

```bash
# Build without tests
mvn clean install -DskipTests

# Run tests
mvn test

# Run with debug logging
mvn spring-boot:run -Dspring-boot.run.arguments=--logging.level.edu.sjsu.cmpe.secainw=DEBUG

# Package for production
mvn clean package -DskipTests
```

---

## Production Deployment

### JVM Optimization

```bash
java -Xmx4g -Xms4g \
  -XX:+UseG1GC \
  -XX:MaxGCPauseMillis=200 \
  -jar target/secainw-backend-0.0.1-SNAPSHOT.jar
```

### Database Connection Pool

```properties
spring.datasource.hikari.maximum-pool-size=20
spring.datasource.hikari.minimum-idle=5
spring.datasource.hikari.connection-timeout=30000
```

### Enable HTTPS

```properties
server.ssl.enabled=true
server.ssl.key-store=classpath:keystore.p12
server.ssl.key-store-password=your-password
server.ssl.key-store-type=PKCS12
```

---

## Security Best Practices

1. **Never commit sensitive data** - Use environment variables
2. **Use strong JWT secrets** - Minimum 256 bits
3. **Enable HTTPS in production**
4. **Implement rate limiting**
5. **Keep dependencies updated**
   ```bash
   mvn versions:display-dependency-updates
   ```

---

## Testing the Application

### Health Check
```bash
curl http://localhost:8080/actuator/health
```

### Complete Workflow
1. Register a user via `/api/auth/signup`
2. Login to get JWT token via `/api/auth/login`
3. Use token to access protected endpoints
4. Import dataset via `/api/lanl/import/*`
5. Detect anomalies via `/api/anomalies/detect`
6. Generate reports via `/api/reports/generate`

---

## Additional Resources

- **Spring Boot Documentation:** https://spring.io/projects/spring-boot
- **Spring AI Documentation:** https://docs.spring.io/spring-ai/reference/
- **Oracle AI Database:** https://www.oracle.com/database/
- **JWT Best Practices:** https://jwt.io/
