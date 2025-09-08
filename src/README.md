# Account Management System

A blockchain account management system built with Go using Clean Architecture principles.

## Architecture

This project follows Clean Architecture principles with the following layers:

- **Domain Layer**: Contains business entities, repository interfaces, and service interfaces
- **Application Layer**: Contains business logic implementation and DTOs
- **Infrastructure Layer**: Contains database implementations, external services, and caching
- **Presentation Layer**: Contains HTTP handlers, middleware, and routing

## Project Structure

```
src/
├── cmd/                          # Application entry points
│   └── server/
│       └── main.go
├── internal/                     # Internal packages (not importable from outside)
│   ├── config/                   # Configuration management
│   ├── domain/                   # Domain layer
│   │   ├── entities/            # Business entities
│   │   ├── repositories/        # Repository interfaces
│   │   └── services/           # Service interfaces
│   ├── application/             # Application layer
│   │   ├── services/           # Business logic implementation
│   │   └── dto/               # Data transfer objects
│   ├── infrastructure/         # Infrastructure layer
│   │   ├── database/          # Database related
│   │   ├── external/         # External services
│   │   └── cache/           # Caching implementation
│   └── presentation/          # Presentation layer
│       ├── http/             # HTTP handlers and middleware
│       └── grpc/            # gRPC server (optional)
├── pkg/                      # Public packages
├── api/                     # API documentation
├── scripts/                # Scripts
├── deployments/           # Deployment configurations
├── configs/              # Configuration files
├── docs/                # Documentation
├── tests/              # Test files
├── go.mod
├── go.sum
├── Makefile
└── README.md
```

## Features

- **User Management**: User registration, authentication, and profile management
- **Wallet Management**: Multi-blockchain wallet support (Ethereum, TRON)
- **Transaction Tracking**: Real-time transaction monitoring and history
- **Balance Management**: Multi-currency balance tracking
- **Withdrawal System**: Secure withdrawal processing
- **Notification System**: Telegram notifications for important events
- **Encryption**: AES-256 encryption for private keys

## Getting Started

### Prerequisites

- Go 1.21 or higher
- PostgreSQL 15 or higher
- Redis (optional, for caching)

### Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd account-management
```

2. Install dependencies:
```bash
make deps
```

3. Set up environment variables:
```bash
cp configs/config.dev.yaml configs/config.yaml
# Edit config.yaml with your settings
```

4. Run database migrations:
```bash
make migrate
```

5. Start the application:
```bash
make run
```

### Using Docker

1. Build and run with Docker Compose:
```bash
cd deployments/docker
docker-compose up --build
```

## Configuration

The application uses environment variables for configuration. See `configs/` directory for example configurations.

### Required Environment Variables

- `DB_URL`: Database host
- `DB_PORT`: Database port
- `DB_USER`: Database username
- `DB_PASSWORD`: Database password
- `DB_DATABASE`: Database name
- `SERVER_PORT`: Server port

### Optional Environment Variables

- `ETHEREUM_RPC_URL`: Ethereum RPC endpoint
- `TRON_RPC_URL`: TRON RPC endpoint
- `TELEGRAM_BOT_TOKEN`: Telegram bot token
- `TELEGRAM_CHAT_ID`: Telegram chat ID

## API Endpoints

### Health Check
- `GET /health` - Health check endpoint

### Address Management
- `GET /api/v1/ether-address` - Get Ethereum address
- `GET /api/v1/tron-address` - Get TRON address
- `GET /api/v1/address` - Get all addresses

### Balance and Transactions
- `GET /api/v1/balance` - Get wallet balance
- `POST /api/v1/collect` - Collect funds
- `POST /api/v1/send` - Send funds

### Withdrawal
- `POST /api/v1/withdraw` - Process withdrawal
- `POST /api/v1/manual-request` - Manual withdrawal request

## Development

### Running Tests
```bash
make test
```

### Running Tests with Coverage
```bash
make test-coverage
```

### Code Formatting
```bash
make fmt
```

### Linting
```bash
make lint
```

### Hot Reload (Development)
```bash
make dev
```

## Deployment

### Docker
```bash
make docker-build
make docker-run
```

### Kubernetes
```bash
kubectl apply -f deployments/kubernetes/
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.
