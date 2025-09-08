# 시작 이미지로 golang의 공식 이미지 사용
FROM golang:1.22

# 작업 디렉토리 설정
WORKDIR /app

# 소스 코드 복사
COPY ./src/go.mod ./
COPY ./src/go.sum ./
RUN go mod download
COPY ./src/*.* ./
COPY ./src/cmd/main.go ./cmd/main.go

WORKDIR /app/cmd

# 애플리케이션 빌드
RUN go build -o main .

EXPOSE 6214

# 애플리케이션 실행
CMD ["./main"]
