FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    CUDA_VISIBLE_DEVICES=""

WORKDIR /app

COPY api/runtime-requirements.txt /tmp/runtime-requirements.txt
RUN pip install --no-cache-dir \
    --index-url https://download.pytorch.org/whl/cpu \
    --extra-index-url https://pypi.org/simple \
    "torch>=2.2,<3.0"
RUN pip install --no-cache-dir -r /tmp/runtime-requirements.txt

# Copy application code only. Datasets, evaluation outputs, and trained model
# artifacts are supplied at runtime through read-only volume mounts.
COPY api ./api
COPY models ./models

EXPOSE 8000

CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000"]
