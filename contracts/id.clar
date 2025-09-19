;; Decentralized Identity & Credential Verification Smart Contract
;; Manages digital identities, verifiable credentials, and trust networks

;; Error Constants
(define-constant ERR-UNAUTHORIZED-ACCESS (err u100))
(define-constant ERR-INVALID-IDENTITY-ID (err u101))
(define-constant ERR-IDENTITY-NOT-FOUND (err u102))
(define-constant ERR-CREDENTIAL-EXPIRED (err u103))
(define-constant ERR-INSUFFICIENT-REPUTATION (err u104))
(define-constant ERR-INVALID-SIGNATURE (err u105))
(define-constant ERR-ALREADY-EXISTS (err u106))
(define-constant ERR-INVALID-DURATION (err u107))
(define-constant ERR-VERIFICATION-FAILED (err u108))
(define-constant ERR-INVALID-PRINCIPAL (err u109))
(define-constant ERR-CREDENTIAL-REVOKED (err u110))
(define-constant ERR-INVALID-CREDENTIAL-TYPE (err u111))
(define-constant ERR-TRUST-VIOLATION (err u112))
(define-constant ERR-LIST-FULL (err u113))
(define-constant ERR-INVALID-INPUT (err u114))
(define-constant ERR-ISSUER-NOT-AUTHORIZED (err u115))

;; Validation Constants
(define-constant MIN-REPUTATION-SCORE u0)
(define-constant MAX-REPUTATION-SCORE u1000)
(define-constant MIN-CREDENTIAL-DURATION u144) ;; ~1 day in blocks
(define-constant MAX-CREDENTIAL-DURATION u525600) ;; ~1 year in blocks
(define-constant MIN-TRUST-SCORE u1)
(define-constant MAX-TRUST-SCORE u100)

;; Contract Constants
(define-constant contract-deployer tx-sender)
(define-constant identity-registry-name "decentralized-identity-system")

;; Data Variables
(define-data-var next-identity-id uint u1)
(define-data-var next-credential-id uint u1)
(define-data-var registry-admin principal contract-deployer)
(define-data-var verification-fee uint u100000) ;; 0.1 STX in microSTX
(define-data-var min-issuer-reputation uint u500) ;; Minimum reputation to issue credentials

;; Credential Types
(define-constant TYPE-EDUCATION u1)
(define-constant TYPE-PROFESSIONAL u2)
(define-constant TYPE-IDENTITY u3)
(define-constant TYPE-SKILL u4)
(define-constant TYPE-CERTIFICATION u5)

;; Identity Status
(define-constant STATUS-ACTIVE u1)
(define-constant STATUS-SUSPENDED u2)
(define-constant STATUS-VERIFIED u3)
(define-constant STATUS-FLAGGED u4)

;; Credential Status
(define-constant CRED-STATUS-VALID u1)
(define-constant CRED-STATUS-EXPIRED u2)
(define-constant CRED-STATUS-REVOKED u3)
(define-constant CRED-STATUS-PENDING u4)

;; Trust Levels
(define-constant TRUST-UNKNOWN u0)
(define-constant TRUST-LOW u1)
(define-constant TRUST-MEDIUM u2)
(define-constant TRUST-HIGH u3)

;; Data Maps
(define-map digital-identities
  { identity-id: uint }
  {
    owner: principal,
    public-key: (buff 33),
    reputation-score: uint,
    trust-level: uint,
    created-at: uint,
    last-updated: uint,
    status: uint,
    verification-count: uint,
    credentials-issued: uint,
    credentials-received: uint
  }
)

(define-map identity-profiles
  { identity-id: uint }
  {
    display-name: (string-ascii 50),
    bio: (string-ascii 200),
    website: (string-ascii 100),
    location: (string-ascii 50),
    profile-hash: (string-ascii 64)
  }
)

(define-map verifiable-credentials
  { credential-id: uint }
  {
    holder: principal,
    issuer: principal,
    credential-type: uint,
    subject: (string-ascii 100),
    claim-data: (string-ascii 500),
    issued-at: uint,
    expires-at: uint,
    status: uint,
    verification-count: uint,
    trust-score: uint
  }
)

(define-map credential-metadata
  { credential-id: uint }
  {
    title: (string-ascii 100),
    description: (string-ascii 300),
    issuer-name: (string-ascii 50),
    credential-hash: (string-ascii 64),
    evidence-url: (string-ascii 200)
  }
)

(define-map identity-credentials
  { identity-owner: principal }
  { 
    issued-credentials: (list 50 uint),
    received-credentials: (list 100 uint),
    verified-credentials: (list 100 uint)
  }
)

(define-map trust-relationships
  { truster: principal, trustee: principal }
  {
    trust-level: uint,
    reputation-boost: uint,
    created-at: uint,
    last-interaction: uint
  }
)

(define-map verification-records
  { credential-id: uint, verifier: principal }
  {
    verification-result: bool,
    trust-impact: uint,
    timestamp: uint,
    notes: (string-ascii 200)
  }
)

(define-map authorized-issuers
  { issuer: principal, credential-type: uint }
  {
    authorized: bool,
    authorization-level: uint,
    authorized-at: uint,
    authorized-by: principal
  }
)

;; Private Functions

(define-private (is-registry-admin (user principal))
  (is-eq user (var-get registry-admin))
)

(define-private (is-valid-credential-type (cred-type uint))
  (and (>= cred-type TYPE-EDUCATION) (<= cred-type TYPE-CERTIFICATION))
)

(define-private (is-valid-trust-level (level uint))
  (and (>= level TRUST-UNKNOWN) (<= level TRUST-HIGH))
)

(define-private (is-valid-reputation (score uint))
  (and (>= score MIN-REPUTATION-SCORE) (<= score MAX-REPUTATION-SCORE))
)

(define-private (is-valid-duration (duration uint))
  (and (>= duration MIN-CREDENTIAL-DURATION) (<= duration MAX-CREDENTIAL-DURATION))
)

(define-private (is-valid-trust-score (score uint))
  (and (>= score MIN-TRUST-SCORE) (<= score MAX-TRUST-SCORE))
)

(define-private (is-valid-string-ascii-50 (input (string-ascii 50)))
  (and (> (len input) u0) (<= (len input) u50))
)

(define-private (is-valid-string-ascii-100 (input (string-ascii 100)))
  (and (> (len input) u0) (<= (len input) u100))
)

(define-private (is-valid-string-ascii-200 (input (string-ascii 200)))
  (and (> (len input) u0) (<= (len input) u200))
)

(define-private (is-valid-string-ascii-300 (input (string-ascii 300)))
  (and (> (len input) u0) (<= (len input) u300))
)

(define-private (is-valid-string-ascii-500 (input (string-ascii 500)))
  (and (> (len input) u0) (<= (len input) u500))
)

(define-private (is-valid-identity-id (identity-id uint))
  (and (> identity-id u0) (< identity-id (var-get next-identity-id)))
)

(define-private (is-valid-credential-id (credential-id uint))
  (and (> credential-id u0) (< credential-id (var-get next-credential-id)))
)

(define-private (is-valid-principal (user principal))
  (not (is-eq user 'SP000000000000000000002Q6VF78))
)

(define-private (get-current-block)
  block-height
)

(define-private (is-credential-valid (cred-data (optional {holder: principal, issuer: principal, credential-type: uint, subject: (string-ascii 100), claim-data: (string-ascii 500), issued-at: uint, expires-at: uint, status: uint, verification-count: uint, trust-score: uint})))
  (match cred-data
    credential (and 
                (is-eq (get status credential) CRED-STATUS-VALID)
                (> (get expires-at credential) (get-current-block)))
    false
  )
)

(define-private (calculate-reputation-boost (trust-level uint) (verification-count uint))
  (+ (* trust-level u10) (/ verification-count u5))
)

(define-private (is-authorized-issuer (issuer principal) (cred-type uint))
  (match (map-get? authorized-issuers { issuer: issuer, credential-type: cred-type })
    authorization (get authorized authorization)
    false
  )
)

(define-private (get-identity-id (owner principal))
  ;; This would typically involve a reverse lookup map, simplified for demo
  (some u1) ;; Placeholder - in production, implement proper identity-to-ID mapping
)

(define-private (add-credential-to-identity (identity-owner principal) (credential-id uint) (is-issuer bool))
  (let ((current-data (default-to { 
          issued-credentials: (list), 
          received-credentials: (list), 
          verified-credentials: (list) 
        } (map-get? identity-credentials { identity-owner: identity-owner }))))
    (if is-issuer
      (match (as-max-len? (append (get issued-credentials current-data) credential-id) u50)
        updated-issued (begin
                         (map-set identity-credentials 
                                  { identity-owner: identity-owner }
                                  (merge current-data { issued-credentials: updated-issued }))
                         (ok true))
        ERR-LIST-FULL)
      (match (as-max-len? (append (get received-credentials current-data) credential-id) u100)
        updated-received (begin
                           (map-set identity-credentials 
                                    { identity-owner: identity-owner }
                                    (merge current-data { received-credentials: updated-received }))
                           (ok true))
        ERR-LIST-FULL)
    )
  )
)

;; Read-only Functions

(define-read-only (get-digital-identity (identity-id uint))
  (map-get? digital-identities { identity-id: identity-id })
)

(define-read-only (get-identity-profile (identity-id uint))
  (map-get? identity-profiles { identity-id: identity-id })
)

(define-read-only (get-verifiable-credential (credential-id uint))
  (map-get? verifiable-credentials { credential-id: credential-id })
)

(define-read-only (get-credential-metadata (credential-id uint))
  (map-get? credential-metadata { credential-id: credential-id })
)

(define-read-only (get-identity-credentials (identity-owner principal))
  (map-get? identity-credentials { identity-owner: identity-owner })
)

(define-read-only (get-trust-relationship (truster principal) (trustee principal))
  (map-get? trust-relationships { truster: truster, trustee: trustee })
)

(define-read-only (get-verification-record (credential-id uint) (verifier principal))
  (map-get? verification-records { credential-id: credential-id, verifier: verifier })
)

(define-read-only (is-authorized-issuer-check (issuer principal) (credential-type uint))
  (is-authorized-issuer issuer credential-type)
)

(define-read-only (get-next-identity-id)
  (var-get next-identity-id)
)

(define-read-only (get-next-credential-id)
  (var-get next-credential-id)
)

(define-read-only (is-credential-active (credential-id uint))
  (let ((credential-data (get-verifiable-credential credential-id)))
    (is-credential-valid credential-data)
  )
)

(define-read-only (calculate-trust-score (identity-owner principal))
  (match (get-identity-credentials identity-owner)
    cred-data (ok {
      received-count: (len (get received-credentials cred-data)),
      issued-count: (len (get issued-credentials cred-data)),
      verified-count: (len (get verified-credentials cred-data))
    })
    ERR-IDENTITY-NOT-FOUND
  )
)

;; Public Functions

(define-public (create-digital-identity 
                (public-key (buff 33))
                (display-name (string-ascii 50))
                (bio (string-ascii 200))
                (website (string-ascii 100))
                (location (string-ascii 50)))
  (let ((identity-id (var-get next-identity-id))
        (current-block (get-current-block)))
    
    ;; Input validation
    (asserts! (is-valid-string-ascii-50 display-name) ERR-INVALID-INPUT)
    (asserts! (is-valid-string-ascii-200 bio) ERR-INVALID-INPUT)
    (asserts! (is-valid-string-ascii-100 website) ERR-INVALID-INPUT)
    (asserts! (is-valid-string-ascii-50 location) ERR-INVALID-INPUT)
    (asserts! (> (len public-key) u0) ERR-INVALID-INPUT)
    
    ;; Create identity record
    (map-set digital-identities
             { identity-id: identity-id }
             {
               owner: tx-sender,
               public-key: public-key,
               reputation-score: u100, ;; Starting reputation
               trust-level: TRUST-LOW,
               created-at: current-block,
               last-updated: current-block,
               status: STATUS-ACTIVE,
               verification-count: u0,
               credentials-issued: u0,
               credentials-received: u0
             })
    
    ;; Create profile
    (map-set identity-profiles
             { identity-id: identity-id }
             {
               display-name: display-name,
               bio: bio,
               website: website,
               location: location,
               profile-hash: "" ;; Could be IPFS hash
             })
    
    ;; Initialize credential tracking
    (map-set identity-credentials
             { identity-owner: tx-sender }
             { 
               issued-credentials: (list),
               received-credentials: (list),
               verified-credentials: (list)
             })
    
    ;; Increment identity ID counter
    (var-set next-identity-id (+ identity-id u1))
    
    (ok identity-id)
  )
)

;; Adding issue-verifiable-credential public function
(define-public (issue-verifiable-credential
                (holder principal)
                (credential-type uint)
                (subject (string-ascii 100))
                (claim-data (string-ascii 500))
                (duration uint)
                (title (string-ascii 100))
                (description (string-ascii 300))
                (evidence-url (string-ascii 200)))
  (let ((credential-id (var-get next-credential-id))
        (current-block (get-current-block))
        (expires-at (+ current-block duration)))
    
    ;; Input validation
    (asserts! (is-valid-principal holder) ERR-INVALID-PRINCIPAL)
    (asserts! (is-valid-credential-type credential-type) ERR-INVALID-CREDENTIAL-TYPE)
    (asserts! (is-valid-string-ascii-100 subject) ERR-INVALID-INPUT)
    (asserts! (is-valid-string-ascii-500 claim-data) ERR-INVALID-INPUT)
    (asserts! (is-valid-duration duration) ERR-INVALID-DURATION)
    (asserts! (is-valid-string-ascii-100 title) ERR-INVALID-INPUT)
    (asserts! (is-valid-string-ascii-300 description) ERR-INVALID-INPUT)
    (asserts! (is-valid-string-ascii-200 evidence-url) ERR-INVALID-INPUT)
    
    ;; Check if issuer is authorized for this credential type
    (asserts! (is-authorized-issuer tx-sender credential-type) ERR-ISSUER-NOT-AUTHORIZED)
    
    ;; Create credential record
    (map-set verifiable-credentials
             { credential-id: credential-id }
             {
               holder: holder,
               issuer: tx-sender,
               credential-type: credential-type,
               subject: subject,
               claim-data: claim-data,
               issued-at: current-block,
               expires-at: expires-at,
               status: CRED-STATUS-VALID,
               verification-count: u0,
               trust-score: u50 ;; Initial trust score
             })
    
    ;; Create credential metadata
    (map-set credential-metadata
             { credential-id: credential-id }
             {
               title: title,
               description: description,
               issuer-name: "", ;; Could be populated from issuer's profile
               credential-hash: "", ;; Could be hash of credential data
               evidence-url: evidence-url
             })
    
    ;; Add credential to issuer's issued list
    (try! (add-credential-to-identity tx-sender credential-id true))
    
    ;; Increment credential ID counter
    (var-set next-credential-id (+ credential-id u1))
    
    (ok credential-id)
  )
)

