"""
Défi — Détection de fraude financière.

Vous devez implémenter la fonction `detect_fraud`.
La fonction `load_transactions` vous est FOURNIE (ne la modifiez pas).
"""

import csv


def load_transactions(path):
    """Lit un fichier CSV de transactions et renvoie une liste de dicts."""
    transactions = []
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            transactions.append(_clean_row(row))
    return transactions


def _clean_row(row):
    def get(key):
        v = row.get(key)
        return v.strip() if isinstance(v, str) and v.strip() != "" else None

    amount_raw = get("amount")
    try:
        amount = float(amount_raw) if amount_raw is not None else None
    except ValueError:
        amount = None

    card_raw = get("card_present")
    if card_raw is None:
        card_present = None
    else:
        card_present = card_raw.lower() in ("true", "1", "yes", "oui")

    return {
        "transaction_id": get("transaction_id"),
        "timestamp": get("timestamp"),
        "user_id": get("user_id"),
        "amount": amount,
        "currency": get("currency"),
        "merchant": get("merchant"),
        "country": get("country"),
        "card_present": card_present,
    }


def detect_fraud(transactions):
    """Analyse une liste de transactions et renvoie un verdict pour chacune.

    Retour : list[dict] avec transaction_id, fraud_score (0-1),
    is_suspicious (bool), reason (str) — un résultat par transaction, même ordre.
    """
   
    results = []
    
    # --- ÉTAPE A : HISTORIQUE GLOBAL ---
    # On crée le dictionnaire des montants par utilisateur
    historique_utilisateurs = {}
    for tx in transactions:
        u_id = tx.get("user_id")
        montant = tx.get("amount")
        if u_id and montant is not None and montant > 0:
            if u_id not in historique_utilisateurs:
                historique_utilisateurs[u_id] = []
            historique_utilisateurs[u_id].append(montant)
            
    # --- ÉTAPE B : ENTRER DANS LA DÉTECTION ---
    for tx in transactions:
        tx_id = tx.get("transaction_id")
        user_id = tx.get("user_id")
        amount = tx.get("amount")
        
        # Valeurs par défaut
        fraud_score = 0.0
        is_suspicious = False
        reason = "Transaction légitime"
        
        # 1. Filtres du Niveau 1 (Anomalies évidentes)
        if not user_id:
            fraud_score = 1.0
            is_suspicious = True
            reason = "Alerte : Identifiant utilisateur manquant"
            
        elif amount is None or amount <= 0:
            fraud_score = 1.0
            is_suspicious = True
            reason = "Alerte : Montant invalide, nul ou négatif"
            
        # 2. LOGIQUE NIVEAU 2 : Détection par rapport au vrai historique passé
        else:
            all_montants = historique_utilisateurs.get(user_id, [])
            
            # On retire le montant de la transaction actuelle pour avoir le VRAI historique passé
            montants_passes = [m for m in all_montants]
            if amount in montants_passes:
                montants_passes.remove(amount) # On enlève la transaction en cours de l'historique
            
            # Si le client a un historique passé (au moins une transaction avant celle-ci)
            if len(montants_passes) >= 1:
                moyenne_passee = sum(montants_passes) / len(montants_passes)
                
                # SEUIL : Si le montant actuel fait plus de 10 fois sa moyenne passée
                if amount > moyenne_passee * 10:
                    fraud_score = 0.9
                    is_suspicious = True
                    reason = f"Alerte : Montant anormalement élevé (Moyenne habituelle : {moyenne_passee})"
        
        # On ajoute le résultat
        results.append({
            "transaction_id": tx_id,
            "fraud_score": fraud_score,
            "is_suspicious": is_suspicious,
            "reason": reason
        })
        
    return results
    raise NotImplementedError("Implémentez detect_fraud")
