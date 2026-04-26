"""
WebSec Lab — Punto de entrada
Ejecutar con: python run.py
"""
from app import create_app

app = create_app()

if __name__ == "__main__":
    print("\n" + "="*60)
    print("  WebSec Lab — Sistema de Seguridad Web")
    print("  URL: http://localhost:5000")
    print("  Usuarios: admin / analyst / demo")
    print("  Contraseñas: Admin123! / Analyst123! / Demo1234!")
    print("="*60 + "\n")
    app.run(debug=False, host="0.0.0.0", port=5000)
