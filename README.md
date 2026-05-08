# Criptografia RSA e Assinaturas Digitais: Implementação Nativa e OAEP

Este repositório contém o **Trabalho 2** da disciplina de **Segurança Computacional (CIC0201)** do Departamento de Ciência da Computação da **Universidade de Brasília (UnB)**, sob orientação da **Profa. Priscila Solis**.

O projeto consiste no desenvolvimento de uma ferramenta de linha de comando (CLI) em Python para geração de chaves assimétricas, cifração com preenchimento seguro e um sistema completo de assinatura e verificação digital de arquivos.

## Funcionalidades

O sistema está dividido em dois módulos principais integrados por uma interface de terminal:

1.  **Geração de Chaves e Cifração (Confidencialidade):**
    * **Geração Segura:** Teste de primalidade de **Miller-Rabin** para encontrar números primos grandes (mínimo de 1024 bits) e cálculo manual das chaves públicas e privadas.
    * **Preenchimento OAEP:** Implementação do *Optimal Asymmetric Encryption Padding* construído do zero, transformando o RSA determinístico em um esquema probabilístico seguro contra ataques de texto cifrado escolhido.
    * Cifração e decifração de arquivos por blocos.

2.  **Assinatura Digital (Autenticidade e Integridade):**
    * **Geração de Hash:** Cálculo do resumo criptográfico do documento original utilizando a função **SHA-3**.
    * **Assinatura e Formatação:** Cifração do hash com a chave privada e estruturação do pacote final em formato **JSON**, utilizando codificação **BASE64** para garantir o transporte seguro de dados binários.
    * **Verificação:** Parsing automatizado do documento JSON, recuperação da assinatura com a chave pública e validação da integridade comparando com um novo cálculo de hash.

## Fundamentação Técnica

O sistema garante as propriedades fundamentais de segurança construindo a matemática por trás dos algoritmos. A confidencialidade é assegurada mitigando as vulnerabilidades do "RSA de livro" através das máscaras geradas pelo MGF1 dentro do OAEP. Simultaneamente, o processo de assinatura inverte o uso das chaves: a chave privada assina o hash SHA-3 do arquivo, permitindo que a chave pública comprove inequivocamente a identidade do emissor e garanta que nem um único bit do documento foi adulterado.

## Tecnologias Utilizadas

* **Linguagem:** [Python 3.x](https://www.python.org/)
* **Interface:** Linha de Comando (CLI) utilizando `argparse`.
* **Bibliotecas:** Apenas bibliotecas nativas da linguagem (como `hashlib` estritamente para o SHA-3, `secrets` para entropia criptográfica verdadeira e `base64`). Conforme restrição do roteiro, **nenhuma** biblioteca externa (como OpenSSL ou PyCryptodome) foi utilizada para as primitivas criptográficas principais.
