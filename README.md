# Proteção de Dados com Criptografia Quântica

Repositório de código-fonte da implementação desenvolvida para o Trabalho de Conclusão de Curso (TCC):

> **VIEIRA, Lucas.** *Proteção de Dados com Criptografia Quântica.*
> Trabalho de Conclusão de Curso — Centro Universitário Senac Santo Amaro, 2025.

---

## Objetivo

Este projeto implementa e compara três abordagens de criptografia:

1. **Criptografia Clássica** — AES-256 (simétrica) e RSA-2048 (assimétrica), com coleta de métricas de desempenho.
2. **BB84 Simulado** — Protocolo de Distribuição Quântica de Chaves (QKD) BB84 executado em simulador (`qiskit-aer`), com análise de ruído e simulação de interceptação por Eva.
3. **BB84 em Hardware Real IBM** — Execução do protocolo BB84 em computadores quânticos reais da IBM Quantum Platform via Qiskit Runtime e SamplerV2, com coleta de QBER, taxa de geração de chave e métricas de hardware.

---

## Estrutura do repositório

```
.
├── classical/
│   ├── classic_crypto.py             # Modelo 1: AES-256 e RSA-2048
│   └── resultados_classico/          # Gráficos e métricas gerados
│
├── bb84_simulado/
│   ├── qkd_simulated.py              # Modelo 2: BB84 via AerSimulator
│   └── resultados_bb84/              # Gráficos e métricas gerados
│
├── bb84_hardware_real/
│   ├── qkd_real_v1.py                # Modelo 3a: BB84 IBM (8 qubits)
│   ├── qkd_real_v2.py                # Modelo 3b: BB84 IBM aprimorado (16 qubits)
│   ├── resultados_ibm_real/          # Resultados da v1 (CSV, JSON, PNGs)
│   └── resultados_ibm_bb84_aprimorado/  # Resultados da v2 (CSV, JSON, PNGs)
│
├── .env.example                      # Modelo de variáveis de ambiente
├── .gitignore
├── requirements.txt
└── README.md
```

> **Nota:** Os arquivos JSON de resultados de hardware real (`resultados_ibm_real.json`, `resultados_ibm_bb84_aprimorado.json`) registram métricas experimentais reais. Os campos `job_id` foram anonimizados para preservar a privacidade da conta IBM Quantum utilizada.

---

## Requisitos

- Python 3.10 ou superior
- Conta na [IBM Quantum Platform](https://quantum.ibm.com/) (necessária apenas para o Modelo 3)
- Token de acesso IBM Quantum (necessário apenas para o Modelo 3)

---

## Instalação

```bash
# Clone o repositório
git clone <URL_DO_REPOSITORIO>
cd quantic_criptography

# Crie e ative o ambiente virtual
python -m venv .venv

# Windows (PowerShell)
.venv\Scripts\Activate.ps1

# Linux / macOS
source .venv/bin/activate

# Instale as dependências
pip install -r requirements.txt
```

---

## Configuração das variáveis de ambiente (Modelo 3 — Hardware Real)

Copie o arquivo de exemplo e preencha com suas credenciais IBM Quantum:

```bash
# Copie o arquivo de exemplo
copy .env.example .env    # Windows
cp .env.example .env      # Linux/macOS
```

Edite `.env` com seus dados reais:

```
IBM_QUANTUM_TOKEN=seu_token_real
IBM_QUANTUM_INSTANCE=seu_crn_real
```

Alternativamente, defina as variáveis diretamente na sessão do terminal antes de executar:

```powershell
# Windows PowerShell
$env:IBM_QUANTUM_TOKEN = "seu_token_real"
$env:IBM_QUANTUM_INSTANCE = "seu_crn_real"
```

```bash
# Linux / macOS
export IBM_QUANTUM_TOKEN="seu_token_real"
export IBM_QUANTUM_INSTANCE="seu_crn_real"
```

> **AVISO DE SEGURANÇA:** Nunca commite o arquivo `.env` com tokens reais. O arquivo `.gitignore` já está configurado para ignorá-lo.

---

## Execução

### Modelo 1 — Criptografia Clássica (AES-256 / RSA-2048)

```bash
cd classical
python classic_crypto.py
```

Gera métricas de tempo de cifragem, decifragem e throughput. Os gráficos são salvos em `classical/resultados_classico/`.

---

### Modelo 2 — BB84 Simulado (sem hardware quântico)

```bash
cd bb84_simulado
python qkd_simulated.py
```

Executa o protocolo BB84 via `qiskit-aer` nos cenários:
- Sem ruído (ideal)
- Com ruído quântico (níveis de 0% a 15%)
- Com interceptação por Eva (ataque interceptar-e-reenviar)

Os gráficos são salvos em `bb84_simulado/resultados_bb84/`.

---

### Modelo 3 — BB84 em Hardware Real IBM

> Requer credenciais IBM Quantum configuradas (ver seção anterior).

**Versão v1 (8 qubits — `ibm_marrakesh`):**

```bash
cd bb84_hardware_real
python qkd_real_v1.py
```

**Versão v2 aprimorada (16 qubits, reconciliação e amplificação de privacidade):**

```bash
cd bb84_hardware_real
python qkd_real_v2.py
```

Ambos os scripts:
- Conectam-se automaticamente ao backend IBM com menor fila
- Executam o circuito BB84 com `SamplerV2` via Qiskit Runtime
- Calculam QBER por cenário (sem Eva / com Eva simulada)
- Salvam resultados em CSV, JSON e gráficos PNG na subpasta `resultados_*`

---

## Geração de gráficos e métricas

Os gráficos são gerados automaticamente ao final de cada execução. Cópias dos resultados obtidos durante o TCC já estão incluídas nas subpastas `resultados_*/` de cada modelo.

| Modelo | Pasta de resultados | Arquivos gerados |
|---|---|---|
| Clássico | `classical/resultados_classico/` | 4 PNGs + JSON |
| BB84 Simulado | `bb84_simulado/resultados_bb84/` | 9 PNGs + JSON |
| IBM Real v1 | `bb84_hardware_real/resultados_ibm_real/` | 3 PNGs + CSV + JSON |
| IBM Real v2 | `bb84_hardware_real/resultados_ibm_bb84_aprimorado/` | 3 PNGs + CSV + JSON |

---

## Parâmetros configuráveis (Modelos 3)

| Variável | Padrão | Descrição |
|---|---|---|
| `IBM_QUANTUM_TOKEN` | — | Token de autenticação IBM Quantum |
| `IBM_QUANTUM_INSTANCE` | — | CRN da instância IBM Quantum |
| `IBM_BACKEND` | automático | Nome do backend preferido |
| `N_QUBITS` | 8 (v1) / 16 (v2) | Número de qubits por execução |
| `SHOTS` | 1024 | Medições por circuito |
| `REPETICOES` | 3 | Repetições por cenário |

---

## Referência bibliográfica (ABNT)

```
VIEIRA, Lucas. Proteção de dados com criptografia quântica: código-fonte
da implementação. GitHub, 2025. Disponível em: <URL_DO_REPOSITORIO>.
Acesso em: <DATA_DE_ACESSO>.
```

---

## Trecho sugerido para o TCC

> O código-fonte completo desta implementação, incluindo os três modelos (criptografia clássica, BB84 simulado e BB84 em hardware quântico real IBM), está disponível publicamente em repositório GitHub e pode ser acessado em: \<URL_DO_REPOSITORIO\>.

---

## Licença

Este projeto foi desenvolvido para fins acadêmicos como parte de Trabalho de Conclusão de Curso. Uso, cópia e adaptação são permitidos mediante citação da fonte.
