# 🔐 Analizador de Seguridad de Contraseñas

## Descripción
Herramienta de ciberseguridad en Python que evalúa la fortaleza de contraseñas mediante análisis de entropía, detección de patrones débiles, verificación de contraseñas comunes y estimación de tiempo de crackeo.

## Características
- ✅ Cálculo de entropía (bits de seguridad)
- ✅ Análisis de composición de caracteres
- ✅ Detección de contraseñas comunes
- ✅ Identificación de patrones débiles
- ✅ Detección de palabras del diccionario
- ✅ Verificación de información personal
- ✅ Estimación de tiempo de crackeo
- ✅ Sistema de puntuación (0-100)
- ✅ Recomendaciones personalizadas
- ✅ Entrada segura (contraseña oculta)
- ✅ No almacena ni transmite contraseñas

## Requisitos
- Python 3.6 o superior
- No requiere dependencias externas (solo librerías estándar)

## Instalación
```bash
# Descargar el archivo
wget https://CybersecurityTools-for-Education/passAnalyzer.py

# Dar permisos de ejecución (Linux/Mac)
chmod +x passAnalyzer.py
```

## Uso

### Ejecución básica
```bash
python3 passAnalyzer.py
```

El programa te solicitará ingresar la contraseña de forma segura (no se mostrará en pantalla).

### Ejemplo de uso
```bash
$ python3 passAnalyzer.py
======================================================================
 ANALIZADOR DE SEGURIDAD DE CONTRASEÑAS
======================================================================

💡 Esta herramienta analiza la fortaleza de tus contraseñas
🔒 Tu contraseña NO se almacena ni se envía a ningún servidor

🔑 Ingresa la contraseña a analizar (no se mostrará): 

[*] Analizando contraseña...

======================================================================
 REPORTE DE ANÁLISIS DE CONTRASEÑA
======================================================================

📏 Longitud: 16 caracteres
🔢 Entropía: 85.45 bits
⏱️  Tiempo estimado de crackeo: 3.45 millones de años

📊 COMPOSICIÓN:
   • Minúsculas: 8
   • Mayúsculas: 3
   • Números: 3
   • Especiales: 2

🟢 FORTALEZA: MUY FUERTE 💪
   Puntaje: 85/100
   [██████████████████████████████████████████░░░░░░░░░░]

💡 RECOMENDACIONES (3):
   ✅ ¡Excelente contraseña! Mantenla segura
   💡 Usa un gestor de contraseñas
   💡 Activa autenticación de dos factores (2FA)

======================================================================
```

## Cómo funciona

### 1. Análisis de Entropía
La entropía mide la aleatoriedad de la contraseña en bits:
- **< 28 bits**: Muy débil (crackeada instantáneamente)
- **28-35 bits**: Débil (crackeada en minutos)
- **36-59 bits**: Moderada (crackeada en días/meses)
- **60-127 bits**: Fuerte (años/siglos)
- **128+ bits**: Muy fuerte (prácticamente imposible)

Fórmula: `Entropía = Longitud × log₂(Tamaño del conjunto de caracteres)`

### 2. Sistema de Puntuación
Puntaje basado en múltiples factores (0-100):

**Puntos positivos:**
- Longitud ≥ 12 caracteres: +25 puntos
- Letras minúsculas: +10 puntos
- Letras mayúsculas: +10 puntos
- Números: +10 puntos
- Caracteres especiales: +15 puntos
- Alta entropía: +30 puntos

**Penalizaciones:**
- Contraseña común: -50 puntos
- Patrones débiles: -10 puntos c/u
- Palabras del diccionario: -5 puntos c/u
- Espacios: -5 puntos

### 3. Detección de Vulnerabilidades

#### Contraseñas Comunes
Verifica contra las 100+ contraseñas más usadas:
- password, 123456, qwerty, etc.

#### Patrones Débiles
- Solo números: `12345678`
- Solo letras: `abcdefgh`
- Secuencias: `qwerty`, `123456`
- Caracteres repetidos: `aaaaaaa`
- Palabras clave: `password`, `admin`

#### Información Personal
- Fechas (posibles cumpleaños)
- Años de nacimiento
- Nombres propios

### 4. Estimación de Tiempo de Crackeo
Basado en:
- GPU moderna: 1 billón (10¹²) de intentos/segundo
- Ataque de fuerza bruta
- Considera el espacio total de combinaciones

## Niveles de Fortaleza

### 🔴 MUY DÉBIL (0-19 puntos)
- Crackeada en segundos
- Recomendación: Cambiar inmediatamente

### 🟠 DÉBIL (20-39 puntos)
- Crackeada en minutos/horas
- Recomendación: Mejorar significativamente

### 🟡 MODERADA (40-59 puntos)
- Crackeada en días/semanas
- Recomendación: Fortalecer con más caracteres

### 🟢 FUERTE (60-79 puntos)
- Crackeada en meses/años
- Recomendación: Buen nivel de seguridad

### 🟢 MUY FUERTE (80-100 puntos)
- Crackeada en siglos/milenios
- Recomendación: Excelente contraseña

## Mejores Prácticas

### ✅ Crea contraseñas fuertes
```
❌ Débil:    password123
❌ Débil:    MiNombre2024
⚠️  Moderada: MiC@sa2024
✅ Fuerte:   Mc#4tR$9pLx2Wn8Q
✅ Fuerte:   Correct-Horse-Battery-Staple-97!
```

### ✅ Características de una buena contraseña
1. **Longitud**: Mínimo 12 caracteres (ideal 16+)
2. **Diversidad**: Minúsculas, mayúsculas, números y símbolos
3. **Aleatoriedad**: Sin patrones predecibles
4. **Única**: Diferente para cada cuenta
5. **Memorable**: Usa técnicas como:
   - Frases de contraseña (passphrase)
   - Método de primera letra
   - Sustitución de caracteres aleatoria

### ✅ Lo que NUNCA debes hacer
- ❌ Usar información personal (nombre, fecha nacimiento)
- ❌ Reutilizar contraseñas entre sitios
- ❌ Usar contraseñas comunes o del diccionario
- ❌ Compartir contraseñas
- ❌ Escribir contraseñas en papel o archivos sin cifrar
- ❌ Usar solo un tipo de carácter

## Técnicas de Creación

### Método 1: Generador Aleatorio
```python
import secrets
import string

def generate_password(length=16):
    chars = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(chars) for _ in range(length))
```

### Método 2: Frase de Contraseña (Passphrase)
```
Ejemplo: "Me gusta el café con 3 azúcares!"
Versión segura: "Mg3l€af3€0n3azuc@r3s!"
```

### Método 3: Primera Letra
```
Frase: "Mi perro tiene 4 años y se llama Max en 2024"
Contraseña: "Mpt4aysllMe2024!"
```

## Gestores de Contraseñas Recomendados
- **Bitwarden** (Open Source, multiplataforma)
- **1Password** (Premium, muy seguro)
- **KeePassXC** (Open Source, local)
- **LastPass** (Popular, freemium)

## Integración con APIs

### Have I Been Pwned API
Para verificar filtraciones reales:
```python
import hashlib
import requests

def check_pwned_password(password):
    sha1_hash = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix = sha1_hash[:5]
    suffix = sha1_hash[5:]
    
    response = requests.get(f'https://api.pwnedpasswords.com/range/{prefix}')
    
    for line in response.text.splitlines():
        hash_suffix, count = line.split(':')
        if hash_suffix == suffix:
            return True, int(count)
    
    return False, 0
```

## Seguridad de la Herramienta

### 🔒 Privacidad garantizada
- ✅ Usa `getpass` para entrada segura
- ✅ No almacena contraseñas
- ✅ No envía datos a servidores externos
- ✅ Procesamiento 100% local
- ✅ No genera logs ni archivos

### Limitaciones
- No es un cracker de contraseñas
- Estimaciones basadas en modelos teóricos
- No reemplaza la autenticación de dos factores
- No detecta todas las vulnerabilidades posibles

## Casos de Uso
- 🎓 Educación en seguridad de contraseñas
- 🔍 Auditoría personal de contraseñas
- 👥 Capacitación de usuarios
- 🏢 Políticas de contraseñas corporativas
- 🛡️ Concienciación sobre ciberseguridad

## Extensiones Posibles
1. Integración con Have I Been Pwned API
2. Generador de contraseñas seguras
3. Análisis de múltiples contraseñas desde archivo
4. Detección de patrones de teclado avanzados
5. Soporte para passphrases multi-idioma
6. Exportación de reportes en PDF/HTML

## Contribuir
Puedes mejorar la herramienta agregando:
- Más contraseñas comunes al diccionario
- Patrones débiles adicionales
- Palabras en más idiomas
- Mejores algoritmos de detección

## Recursos Adicionales
- [NIST Password Guidelines](https://pages.nist.gov/800-63-3/)
- [OWASP Password Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [Have I Been Pwned](https://haveibeenpwned.com/)
- [Password Strength Testing Tool (zxcvbn)](https://github.com/dropbox/zxcvbn)

## Autor
Herramienta educativa de ciberseguridad

## Licencia
Uso educativo y personal

## Disclaimer

Esta herramienta proporciona estimaciones educativas. La seguridad real depende de múltiples factores incluyendo el método de ataque, recursos del atacante, y medidas de protección del servicio objetivo. Siempre usa autenticación de dos factores (2FA) cuando esté disponible. El autor no se hace responsable del uso indebido que se le pudieran dar a dichos programas.
