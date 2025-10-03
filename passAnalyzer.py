#!/usr/bin/env python3
"""
Analizador de Seguridad de Contraseñas
Evalúa la fortaleza de contraseñas y detecta vulnerabilidades comunes
"""

import re
import hashlib
import math
import string
import sys
from datetime import datetime
import getpass

# Contraseñas más comunes (top 100 reducido)
COMMON_PASSWORDS = {
    '123456', 'password', '12345678', 'qwerty', '123456789', '12345',
    '1234', '111111', '1234567', 'dragon', '123123', 'baseball', 'iloveyou',
    'trustno1', '1234567890', 'sunshine', 'master', 'welcome', 'shadow',
    'ashley', 'football', 'jesus', 'michael', 'ninja', 'mustang', 'password1',
    'abc123', 'letmein', 'monkey', '696969', 'batman', 'princess', 'solo',
    'admin', 'qwerty123', 'starwars', 'passw0rd', 'superman', 'hello',
    'freedom', 'whatever', 'trustno1', 'charlie', 'aa123456', 'donald',
}

# Patrones comunes débiles
WEAK_PATTERNS = {
    r'^\d+$': 'Solo números',
    r'^[a-z]+$': 'Solo letras minúsculas',
    r'^[A-Z]+$': 'Solo letras mayúsculas',
    r'^(.)\1+$': 'Caracteres repetidos',
    r'12345': 'Secuencia numérica',
    r'qwerty': 'Secuencia de teclado',
    r'abcde': 'Secuencia alfabética',
    r'password': 'Contiene "password"',
    r'admin': 'Contiene "admin"',
    r'user': 'Contiene "user"',
}

# Palabras comunes en español e inglés
COMMON_WORDS = {
    'hola', 'amor', 'casa', 'gato', 'perro', 'nombre', 'hello', 'love',
    'house', 'name', 'welcome', 'bienvenido', 'familia', 'family'
}

def calculate_entropy(password):
    """Calcula la entropía de la contraseña (bits)"""
    if not password:
        return 0
    
    # Determinar el espacio de caracteres
    charset_size = 0
    if any(c.islower() for c in password):
        charset_size += 26
    if any(c.isupper() for c in password):
        charset_size += 26
    if any(c.isdigit() for c in password):
        charset_size += 10
    if any(c in string.punctuation for c in password):
        charset_size += 32
    
    if charset_size == 0:
        return 0
    
    entropy = len(password) * math.log2(charset_size)
    return round(entropy, 2)

def check_common_password(password):
    """Verifica si es una contraseña común"""
    return password.lower() in COMMON_PASSWORDS

def check_weak_patterns(password):
    """Detecta patrones débiles en la contraseña"""
    found_patterns = []
    
    for pattern, description in WEAK_PATTERNS.items():
        if re.search(pattern, password, re.IGNORECASE):
            found_patterns.append(description)
    
    return found_patterns

def check_common_words(password):
    """Detecta palabras comunes en la contraseña"""
    found_words = []
    password_lower = password.lower()
    
    for word in COMMON_WORDS:
        if word in password_lower:
            found_words.append(word)
    
    return found_words

def analyze_composition(password):
    """Analiza la composición de la contraseña"""
    composition = {
        'length': len(password),
        'lowercase': sum(1 for c in password if c.islower()),
        'uppercase': sum(1 for c in password if c.isupper()),
        'digits': sum(1 for c in password if c.isdigit()),
        'special': sum(1 for c in password if c in string.punctuation),
        'spaces': sum(1 for c in password if c.isspace()),
    }
    
    return composition

def check_personal_info_patterns(password):
    """Detecta patrones que podrían ser información personal"""
    warnings = []
    
    # Fechas (formato: dd/mm/yyyy, dd-mm-yyyy, ddmmyyyy)
    if re.search(r'\d{2}[/-]?\d{2}[/-]?\d{2,4}', password):
        warnings.append('⚠️ Posible fecha (evita usar cumpleaños)')
    
    # Años recientes
    if re.search(r'19\d{2}|20\d{2}', password):
        warnings.append('⚠️ Contiene año (evita años de nacimiento)')
    
    # Nombres comunes (patrón simple)
    if re.search(r'[A-Z][a-z]{2,}', password):
        warnings.append('⚠️ Posible nombre propio')
    
    return warnings

def estimate_crack_time(entropy):
    """Estima el tiempo para crackear la contraseña"""
    # Asumiendo 1 billón (10^12) de intentos por segundo (GPU moderna)
    attempts_per_second = 1e12
    total_combinations = 2 ** entropy
    seconds = total_combinations / (2 * attempts_per_second)  # División por 2 (promedio)
    
    # Convertir a unidades legibles
    if seconds < 1:
        return "Instantáneo"
    elif seconds < 60:
        return f"{seconds:.2f} segundos"
    elif seconds < 3600:
        return f"{seconds/60:.2f} minutos"
    elif seconds < 86400:
        return f"{seconds/3600:.2f} horas"
    elif seconds < 31536000:
        return f"{seconds/86400:.2f} días"
    elif seconds < 31536000 * 100:
        return f"{seconds/31536000:.2f} años"
    elif seconds < 31536000 * 1000:
        return f"{seconds/(31536000*100):.2f} siglos"
    else:
        return "Millones de años"

def calculate_strength_score(password, composition, entropy, patterns, common_words):
    """Calcula un puntaje de fortaleza (0-100)"""
    score = 0
    
    # Puntos por longitud
    if composition['length'] >= 12:
        score += 25
    elif composition['length'] >= 8:
        score += 15
    elif composition['length'] >= 6:
        score += 5
    
    # Puntos por diversidad de caracteres
    if composition['lowercase'] > 0:
        score += 10
    if composition['uppercase'] > 0:
        score += 10
    if composition['digits'] > 0:
        score += 10
    if composition['special'] > 0:
        score += 15
    
    # Puntos por entropía
    if entropy >= 80:
        score += 30
    elif entropy >= 60:
        score += 20
    elif entropy >= 40:
        score += 10
    
    # Penalizaciones
    if check_common_password(password):
        score -= 50
    
    score -= len(patterns) * 10
    score -= len(common_words) * 5
    
    if composition['spaces'] > 0:
        score -= 5
    
    return max(0, min(100, score))

def get_strength_label(score):
    """Retorna etiqueta de fortaleza basada en el puntaje"""
    if score >= 80:
        return "MUY FUERTE 💪", "🟢"
    elif score >= 60:
        return "FUERTE 👍", "🟢"
    elif score >= 40:
        return "MODERADA ⚠️", "🟡"
    elif score >= 20:
        return "DÉBIL ❌", "🟠"
    else:
        return "MUY DÉBIL 🚫", "🔴"

def generate_recommendations(password, composition, patterns, common_words):
    """Genera recomendaciones personalizadas"""
    recommendations = []
    
    if composition['length'] < 12:
        recommendations.append("✅ Usa al menos 12 caracteres (ideal: 16+)")
    
    if composition['uppercase'] == 0:
        recommendations.append("✅ Incluye letras mayúsculas")
    
    if composition['lowercase'] == 0:
        recommendations.append("✅ Incluye letras minúsculas")
    
    if composition['digits'] == 0:
        recommendations.append("✅ Incluye números")
    
    if composition['special'] == 0:
        recommendations.append("✅ Incluye caracteres especiales (!@#$%^&*)")
    
    if check_common_password(password):
        recommendations.append("🚨 NUNCA uses contraseñas comunes")
    
    if patterns:
        recommendations.append("🚨 Evita patrones predecibles")
    
    if common_words:
        recommendations.append("⚠️ Evita palabras del diccionario")
    
    if composition['spaces'] > 0:
        recommendations.append("⚠️ Los espacios pueden causar problemas")
    
    if not recommendations:
        recommendations.append("✅ ¡Excelente contraseña! Mantenla segura")
        recommendations.append("💡 Usa un gestor de contraseñas")
        recommendations.append("💡 Activa autenticación de dos factores (2FA)")
    
    return recommendations

def check_password_hash_leak(password):
    """Verifica si la contraseña está en bases de datos de filtraciones (simulado)"""
    # En producción real, usarías Have I Been Pwned API
    # Aquí simulamos verificando contraseñas comunes
    password_hash = hashlib.sha1(password.encode()).hexdigest().upper()
    
    # Simulación: solo contraseñas muy comunes
    if check_common_password(password):
        return True, "millones de veces"
    
    return False, "0"

def analyze_password(password):
    """Realiza análisis completo de la contraseña"""
    print("\n[*] Analizando contraseña...")
    
    # Análisis básico
    composition = analyze_composition(password)
    entropy = calculate_entropy(password)
    
    # Detección de vulnerabilidades
    is_common = check_common_password(password)
    patterns = check_weak_patterns(password)
    common_words = check_common_words(password)
    personal_info = check_personal_info_patterns(password)
    leaked, leak_count = check_password_hash_leak(password)
    
    # Cálculos finales
    score = calculate_strength_score(password, composition, entropy, patterns, common_words)
    strength_label, color = get_strength_label(score)
    crack_time = estimate_crack_time(entropy)
    recommendations = generate_recommendations(password, composition, patterns, common_words)
    
    return {
        'password_length': composition['length'],
        'composition': composition,
        'entropy': entropy,
        'score': score,
        'strength': strength_label,
        'color': color,
        'crack_time': crack_time,
        'is_common': is_common,
        'patterns': patterns,
        'common_words': common_words,
        'personal_info': personal_info,
        'leaked': leaked,
        'leak_count': leak_count,
        'recommendations': recommendations
    }

def print_results(results):
    """Imprime los resultados del análisis"""
    print("\n" + "="*70)
    print(" REPORTE DE ANÁLISIS DE CONTRASEÑA")
    print("="*70)
    
    # Información básica
    print(f"\n📏 Longitud: {results['password_length']} caracteres")
    print(f"🔢 Entropía: {results['entropy']} bits")
    print(f"⏱️  Tiempo estimado de crackeo: {results['crack_time']}")
    
    # Composición
    print(f"\n📊 COMPOSICIÓN:")
    print(f"   • Minúsculas: {results['composition']['lowercase']}")
    print(f"   • Mayúsculas: {results['composition']['uppercase']}")
    print(f"   • Números: {results['composition']['digits']}")
    print(f"   • Especiales: {results['composition']['special']}")
    
    # Fortaleza
    print(f"\n{results['color']} FORTALEZA: {results['strength']}")
    print(f"   Puntaje: {results['score']}/100")
    
    # Barra de progreso
    bar_length = 50
    filled = int(bar_length * results['score'] / 100)
    bar = '█' * filled + '░' * (bar_length - filled)
    print(f"   [{bar}]")
    
    # Vulnerabilidades
    if results['is_common']:
        print(f"\n🚨 ALERTA CRÍTICA: Contraseña extremadamente común")
    
    if results['leaked']:
        print(f"\n🚨 FILTRACIÓN DETECTADA: Aparece {results['leak_count']} en bases de datos comprometidas")
    
    if results['patterns']:
        print(f"\n⚠️  PATRONES DÉBILES DETECTADOS ({len(results['patterns'])}):")
        for pattern in results['patterns']:
            print(f"   • {pattern}")
    
    if results['common_words']:
        print(f"\n⚠️  PALABRAS COMUNES ENCONTRADAS ({len(results['common_words'])}):")
        for word in results['common_words']:
            print(f"   • {word}")
    
    if results['personal_info']:
        print(f"\n⚠️  POSIBLE INFORMACIÓN PERSONAL:")
        for info in results['personal_info']:
            print(f"   • {info}")
    
    # Recomendaciones
    print(f"\n💡 RECOMENDACIONES ({len(results['recommendations'])}):")
    for rec in results['recommendations']:
        print(f"   {rec}")
    
    print("\n" + "="*70 + "\n")

def main():
    print("="*70)
    print(" ANALIZADOR DE SEGURIDAD DE CONTRASEÑAS")
    print("="*70)
    print("\n💡 Esta herramienta analiza la fortaleza de tus contraseñas")
    print("🔒 Tu contraseña NO se almacena ni se envía a ningún servidor\n")
    
    try:
        # Solicitar contraseña de forma segura
        password = getpass.getpass("🔑 Ingresa la contraseña a analizar (no se mostrará): ")
        
        if not password:
            print("\n❌ No ingresaste ninguna contraseña")
            sys.exit(1)
        
        # Analizar
        results = analyze_password(password)
        
        # Mostrar resultados
        print_results(results)
        
        # Opción de analizar otra
        again = input("¿Deseas analizar otra contraseña? (s/n): ").strip().lower()
        if again == 's':
            main()
    
    except KeyboardInterrupt:
        print("\n\n[!] Análisis cancelado")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()