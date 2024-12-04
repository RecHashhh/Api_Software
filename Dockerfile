# Usa una base de Python moderna
FROM python:3.9-slim

# Define el directorio de trabajo en el contenedor
WORKDIR /app

# Copia solo requirements.txt primero para aprovechar el caching
COPY requirements.txt ./

# Actualiza pip y setuptools, e instala dependencias
RUN pip install --no-cache-dir --upgrade pip setuptools \
    && pip install --no-cache-dir -r requirements.txt

# Copia el resto del código de la aplicación
COPY . .

# Comando por defecto para ejecutar tu aplicación (puedes cambiar esto según tu app)
CMD ["python", "src/app.py"]
