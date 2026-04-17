# 1. 파이썬 실행 환경 선택 (가벼운 slim 버전)
FROM python:3.9-slim

# 2. 컨테이너 내부 작업 디렉토리 생성
WORKDIR /app

# 3. 라이브러리 설치 (캐시를 위해 requirements.txt를 먼저 복사)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 4. 소스 코드 전체 복사
COPY . .

# 5. FastAPI 기본 포트 개방
EXPOSE 8000

# 6. 서버 실행 명령어 (EKS에서 환경변수를 주입받아 실행됨)
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]