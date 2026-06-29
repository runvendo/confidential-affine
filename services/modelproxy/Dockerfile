# Tiny OpenAI->Tinfoil model-mapping proxy. Rootless, no deps.
FROM python:3.12-slim
COPY proxy.py /app/proxy.py
USER nobody
EXPOSE 8081
ENTRYPOINT ["python3", "/app/proxy.py"]
