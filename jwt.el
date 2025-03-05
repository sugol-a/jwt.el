(require 'hmac-def)
(require 's)

(defun jwt/sha256 (object)
  "Get the sha256 hash of OBJECT."
  (secure-hash 'sha256 object nil nil t))

(define-hmac-function jwt/hs256 jwt/sha256 64 32)

(defun jwt/plain-get-header (plain)
  (plist-get plain :header))

(defun jwt/plain-get-claims (plain)
  (plist-get plain :claims))

(defun jwt/encode (object)
  (base64url-encode-string (json-encode object) t))

(defun jwt/generate-signature (plain algorithm key)
  (funcall
   algorithm
   (concat
    (jwt/encode (jwt/plain-get-header plain))
    "."
    (jwt/encode (jwt/plain-get-claims plain)))
   key))

(defun jwt/generate (plain algorithm key)
  (let ((signature (jwt/generate-signature plain algorithm key)))
    (concat
     (jwt/encode (jwt/plain-get-header plain))
     "."
     (jwt/encode (jwt/plain-get-claims plain))
     "."
     (base64url-encode-string signature t))))

(defvar jwt-console-buffer
  "*jwt console*")

(defvar jwt-console-header-json nil)
(defvar jwt-console-claims-json nil)
(defvar jwt-console-token nil)

(defvar-local jwt-plain '(:header nil :claims nil))
(defvar-local jwt-key "secret")
(defvar-local jwt-key-is-base64 nil)

(define-derived-mode jwt-console-mode
  fundamental-mode
  "JWT Console"
  "Major mode for jwt-console buffers"
  :interactive t)

(defun jwt--setup-buffer ()
  (kill-all-local-variables)
  (jwt-console-mode)
  (make-local-variable 'jwt-console-header-json)
  (make-local-variable 'jwt-console-claims-json)
  (make-local-variable 'jwt-console-token-json)
  (let ((inhibit-read-only t))
    (erase-buffer))
  (remove-overlays)
  (widget-create 'documentation-string :value "Signing key")
  (widget-create 'editable-field
                 :size 36
                 :value jwt-key
                 :notify
                 (lambda (widget &rest ignore)
                   (setq jwt-key (widget-value widget))
                   (jwt--update-token)))
  (widget-insert " ")
  (widget-create 'checkbox
                 :notify
                 (lambda (widget &rest ignore)
                   (setq jwt-key-is-base64 (widget-value widget))
                   (jwt--update-token)))
  (widget-create 'item
                 :value "Base64")
  (widget-insert "\n")
  (widget-insert (make-string 60 ?—))
  (widget-insert "\n")
  (widget-create 'documentation-string :value "Header")
  (widget-create 'editable-list
                 :entry-format "%d %v\n"
                 :offset 4
                 :notify
                 (lambda (widget &rest ignore)
                   (plist-put jwt-plain :header (jwt--widget-key-value widget))
                   (jwt--update-header)
                   (jwt--update-token))
                 '(group
                   :format "%v"
                   (editable-field
                    :format "Key: %v"
                    :size 16)
                   (editable-field
                    :format " Value: %v"
                    :size 24)))
  (widget-insert "\n")
  (setq jwt-console-header-json (widget-create 'item
                                                     :value ""
                                                     :format " → %v"))
  (widget-insert "\n")
  (widget-insert (make-string 60 ?—))
  (widget-insert "\n")
  (widget-create 'documentation-string :value "Claims")
              (widget-create 'editable-list
                             :entry-format "%d %v\n"
                             :offset 4
                             :notify
                             (lambda (widget &rest ignore)
                               (plist-put jwt-plain :claims (jwt--widget-key-value widget))
                               (jwt--update-claims)
                               (jwt--update-token))
                             '(group
                               :format "%v"
                               (editable-field
                                :format "Key: %v"
                                :size 16)
                               (editable-field
                                :format " Value: %v"
                                :size 24)))
  (widget-insert "\n")
  (setq jwt-console-claims-json (widget-create 'item
                                                     :value ""
                                                     :format " → %v"))
  (widget-insert "\n")
  (widget-insert (make-string 60 ?—))
  (widget-insert "\n\n")
  (widget-create 'documentation-string :value "Token")
  (setq jwt-console-token (widget-create 'item
                                         :value ""
                                         :format "%v"))
  (use-local-map widget-keymap)
  (widget-setup)

  (jwt--update-header)
  (jwt--update-claims)
  (jwt--update-token))

(defun jwt--widget-key-value (widget)
  (mapcar (lambda (child)
            (let* ((value-get (widget-get child :value-get))
                   (child-values (funcall value-get child))
                   (key (car child-values))
                   (value (cadr child-values)))
              (cons key (if (string-match-p "^-?\\(?:[0-9]*[.]\\)?[0-9]+$" value)
                            (string-to-number value)
                          value))))
          (widget-get widget :children)))

(defun jwt--update-token ()
  (when jwt-console-token
    (if-let* ((key (if jwt-key-is-base64
                       (ignore-errors (base64-decode-string jwt-key))
                     jwt-key)))
        (widget-value-set jwt-console-token (jwt/generate jwt-plain #'jwt/hs256 key))
      (message "Key is invalid"))))

(defun jwt--update-header ()
  (when jwt-console-header-json
    (widget-value-set jwt-console-header-json (json-encode (jwt/plain-get-header jwt-plain)))))

(defun jwt--update-claims ()
  (when jwt-console-claims-json
    (widget-value-set jwt-console-claims-json (json-encode (jwt/plain-get-claims jwt-plain)))))

(defun jwt-console ()
  (interactive)
  (let ((buffer (get-buffer-create jwt-console-buffer)))
    (with-current-buffer buffer
      (jwt--setup-buffer))
    (display-buffer buffer)))

(provide 'jwt)
