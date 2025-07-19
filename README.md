# ***TaskSync API***

A powerful Django REST API that synchronizes tasks across multiple productivity platforms including Google Tasks, Notion, and Todoist. Built with Django REST Framework, this API provides seamless task management with real-time synchronization, conflict resolution, and comprehensive OAuth2 integration.

## What is TaskSync API?

TaskSync API is a backend service that acts as a central hub for task management across different platforms. Instead of managing tasks in multiple disconnected apps, TaskSync keeps everything synchronized bidirectionally with intelligent conflict resolution.


## **Key Features**

### **Multi-Platform Sync**
- **Google Tasks** integration with full OAuth2 flow
- **Notion** database synchronization
- **Todoist** project and task management
- **Bidirectional sync** with conflict detection and resolution

### **Enterprise-Grade Security**
- **OAuth2 with PKCE** for secure authentication
- **Encrypted token storage** for external service credentials
- **JWT authentication** with refresh token rotation
- **Account lockout protection** and failed login tracking

### **Advanced Sync Engine**
- **Intelligent conflict resolution** when tasks are modified on multiple platforms
- **Configurable sync frequency** (5 minutes to 24 hours)
- **Background processing** with Celery for scalable operations
- **Error handling and retry logic** with exponential backoff

### **Smart Notifications**
- **Granular notification preferences** per user and provider
- **Quiet hours** support with timezone awareness
- **Email digests** (immediate, hourly, daily, weekly)
- **Sync status notifications** and conflict alerts

### **Analytics & Monitoring**
- **Sync session tracking** with detailed metrics
- **Connection health monitoring** for external services
- **User activity analytics** and usage patterns
- **API request logging** and rate limiting

## **Architecture Overview**

TaskSync API follows a modular Django architecture with clear separation of concerns:

```
tasksync-api/
├── apps/
│   ├── authentication/     # OAuth2, JWT, user management
│   ├── tasks/             # Core task models and business logic
│   ├── sync/              # Synchronization engine and conflict resolution
│   ├── integrations/      # External API providers (Google, Notion, Todoist)
│   ├── notifications/     # Notification system and preferences
│   └── analytics/         # Usage analytics and monitoring
├── config/                # Django settings and configuration
└── tests/                 # Comprehensive test suite
```

## **Development Progress**

### **Completed Components**

#### **Authentication System**
- [x] Custom User model with sync preferences
- [x] OAuth2 state management with PKCE security
- [x] External account management (Google, Notion, Todoist)
- [x] JWT authentication with refresh tokens
- [x] Comprehensive serializers with validation
- [x] Email verification and account security
- [x] Session tracking and security monitoring

#### **Database Design**
- [x] User management with notification preferences
- [x] External account connections with encrypted tokens
- [x] OAuth2 state management for secure flows
- [x] Session tracking for security analytics
- [x] Comprehensive indexing strategy for performance

#### **Security Framework**
- [x] OAuth2 with PKCE implementation ready
- [x] Token encryption for sensitive data
- [x] Account lockout and failed login protection
- [x] CSRF protection with state parameters
- [x] Permission system design

### **In Progress**

#### **API Endpoints**
- [ ] Authentication views and URL routing (IN PROGRESS)
- [ ] OAuth2 service implementation (IN PROGRESS)
- [ ] External account management endpoints (IN PROGRESS)
- [ ] User profile and preferences APIs (IN PROGRESS)

### **Planned Development**

#### **Task Management System**
- [ ] Task, Project, and Label models
- [ ] CRUD operations with advanced filtering
- [ ]  Task relationship management
- [ ]  Bulk operations and batch processing

#### **Synchronization Engine**
- [ ]  Real-time sync with background processing
- [ ]  Conflict detection algorithms
- [ ]  Automatic and manual conflict resolution
- [ ]  Sync session management and analytics

#### **External Integrations**
- [ ]  Google Tasks API integration
- [ ]  Notion API integration  
- [ ]  Todoist API integration
- [ ]  Rate limiting and error handling
- [ ]  Webhook support for real-time updates