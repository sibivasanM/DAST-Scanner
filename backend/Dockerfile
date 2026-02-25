FROM python:3.12-slim-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl unzip wget gnupg ca-certificates \
    libnss3 libatk-bridge2.0-0 libdrm2 libxcomposite1 \
    libxdamage1 libxrandr2 libgbm1 libasound2 libpangocairo-1.0-0 \
    libgtk-3-0 libxshmfence1 libx11-xcb1 libxcb-dri3-0 \
    libdbus-glib-1-2 libatspi2.0-0 \
    fonts-liberation fonts-noto-color-emoji fonts-unifont \
    xvfb xauth dbus \
    && rm -rf /var/lib/apt/lists/*

ARG NUCLEI_VERSION=3.3.7
RUN curl -sSL "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip" \
    -o /tmp/nuclei.zip && \
    unzip /tmp/nuclei.zip -d /usr/local/bin/ && \
    chmod +x /usr/local/bin/nuclei && \
    rm /tmp/nuclei.zip
RUN nuclei -update-templates -silent || true

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
RUN playwright install chromium
COPY . .
RUN mkdir -p /app/screenshots /app/data

# Create Xvfb startup script
RUN echo '#!/bin/bash\nset -e\necho "Starting Xvfb..."\nXvfb :99 -screen 0 1920x1080x24 > /dev/null 2>&1 &\nexport DISPLAY=:99\necho "Display set to :99"\nexec "$@"' > /start.sh && chmod +x /start.sh

EXPOSE 8000
ENTRYPOINT ["/start.sh"]
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
