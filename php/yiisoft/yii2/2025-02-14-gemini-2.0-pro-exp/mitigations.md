# Mitigation Strategies Analysis for yiisoft/yii2

## Mitigation Strategy: [Strict Output Encoding with Yii2's `Html` Helper](./mitigation_strategies/strict_output_encoding_with_yii2's__html__helper.md)

*   **Description:**
    1.  **Identify all output points:** Go through every view file (`.php` files in `views/`) and identify where data is being output.
    2.  **Apply context-aware encoding using `yii\helpers\Html`:**
        *   `Html::encode()`: For general HTML text content.
        *   `Html::encode($data, ENT_QUOTES, 'UTF-8')`: For HTML attributes.
        *   `Html::jsEncode()`: For data embedded within JavaScript code.
        *   `Html::cssEncode()`: For data embedded within CSS styles.
    3.  **Never bypass encoding:** Do not use raw PHP `echo` with user-supplied data without using the `Html` helper.
    4.  **Rich Text Editor Configuration (if using a Yii2 wrapper/extension):** If using a rich text editor *through a Yii2 extension or wrapper*, configure the *Yii2 component* to ensure it sanitizes output and limits allowed HTML tags. This often involves configuring the extension's properties, *not* the editor's native configuration directly.
    5. **Content Security Policy (CSP) using Yii2's Response Component:** Implement CSP headers using Yii2's response component. Example (in `config/web.php`):
        ```php
        'response' => [
            'class' => 'yii\web\Response',
            'on beforeSend' => function ($event) {
                $response = $event->sender;
                $response->headers->set('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline';"); // VERY restrictive, adjust!
            },
        ],
        ```

*   **Threats Mitigated:**
    *   **Cross-Site Scripting (XSS) (Severity: High):**  Yii2's `Html` helper provides the core mechanism for preventing XSS.
    *   **HTML Injection (Severity: Medium):**  Again, the `Html` helper is the primary defense.

*   **Impact:**
    *   **XSS:** Risk significantly reduced (80-90%) with consistent use of Yii2's encoding functions.
    *   **HTML Injection:** Risk significantly reduced (90%).

*   **Currently Implemented:**
    *   `Html::encode()` is used in most view files.

*   **Missing Implementation:**
    *   `Html::jsEncode()` and `Html::cssEncode()` are not consistently used.
    *   CSP implementation is basic and needs refinement.
    *   Yii2 wrapper for CKEditor is not configured to restrict allowed HTML tags (assuming a Yii2 wrapper is used).

## Mitigation Strategy: [Enable and Enforce Yii2's CSRF Protection](./mitigation_strategies/enable_and_enforce_yii2's_csrf_protection.md)

*   **Description:**
    1.  **Global Enablement (Yii2 Config):** In `config/web.php`, ensure the `request` component has `enableCsrfValidation` set to `true`:
        ```php
        'request' => [
            'enableCsrfValidation' => true,
            // ... other settings ...
        ],
        ```
    2.  **`ActiveForm` Usage:** Use Yii2's `ActiveForm` widget for all forms. This *automatically* handles CSRF token inclusion.
    3.  **Manual Forms (Include Yii2's CSRF Token):** If creating forms manually, include the CSRF token using Yii2's helpers:
        ```php
        <input type="hidden" name="<?= Yii::$app->request->csrfParam; ?>" value="<?= Yii::$app->request->getCsrfToken(); ?>">
        ```
    4.  **AJAX Requests (Use Yii2's CSRF Token):** Include the CSRF token in AJAX requests, preferably using Yii2's JavaScript helper:
        ```javascript
        $.ajax({
            url: '...',
            type: 'POST',
            data: {
                _csrf: yii.getCsrfToken(), // Yii2's JavaScript helper
                // ... other data ...
            },
            success: function(data) { ... }
        });
        ```
    5. **Per-Action Disabling (Discouraged, but Yii2-Specific):**  If *absolutely* necessary, disable CSRF for a specific action using the `$enableCsrfValidation` property of the *Yii2 controller or action*: `$this->enableCsrfValidation = false;` (within the controller action).  Document the reason.

*   **Threats Mitigated:**
    *   **Cross-Site Request Forgery (CSRF) (Severity: High):**  Yii2's built-in CSRF protection is the primary mitigation.

*   **Impact:**
    *   **CSRF:** Risk reduced significantly (95%+) when Yii2's CSRF protection is properly implemented.

*   **Currently Implemented:**
    *   `enableCsrfValidation` is `true` globally.
    *   `ActiveForm` is used for most forms.

*   **Missing Implementation:**
    *   Some older forms are manual and lack the Yii2-generated CSRF token.
    *   AJAX requests in one module don't use `yii.getCsrfToken()`.

## Mitigation Strategy: [Parameterized Queries with Yii2's Active Record and Query Builder](./mitigation_strategies/parameterized_queries_with_yii2's_active_record_and_query_builder.md)

*   **Description:**
    1.  **Active Record/Query Builder:** Use Yii2's Active Record or Query Builder for *all* database interactions. These *automatically* handle parameterization.  Example (Active Record):
        ```php
        $user = User::findOne(['username' => $username]); // Parameterized by Yii2
        ```
        Example (Query Builder):
        ```php
        $users = (new \yii\db\Query())
            ->select(['id', 'username'])
            ->from('user')
            ->where(['status' => 1])
            ->andWhere(['like', 'username', $search]) // Parameterized 'like' by Yii2
            ->all();
        ```
    2.  **Avoid `rawSql()` (or use Yii2's Parameterization):**  Do *not* use `yii\db\Command::rawSql()` unless unavoidable. If you *must*, use Yii2's parameter binding:
        ```php
        $command = Yii::$app->db->createCommand("SELECT * FROM user WHERE id = :id");
        $command->bindValue(':id', $id); // Yii2's parameter binding
        $user = $command->queryOne();
        ```
    3. **Input Validation using Yii2 Model Rules:** Use Yii2's model validation rules to validate *all* user input *before* it's used in database queries (even though Active Record/Query Builder parameterize, this is defense-in-depth). Example (in the `User` model):
         ```php
        public function rules()
        {
            return [
                [['username', 'email'], 'required'],
                ['username', 'string', 'min' => 4, 'max' => 255],
                ['email', 'email'],
                // ... other rules ...
            ];
        }
        ```

*   **Threats Mitigated:**
    *   **SQL Injection (Severity: Critical):** Yii2's Active Record and Query Builder, when used correctly, are the primary defense against SQL injection.
    *   **Data Type Mismatches (Severity: Low):** Yii2's model validation rules help prevent this.

*   **Impact:**
    *   **SQL Injection:** Risk reduced to near zero (99%+) with consistent use of Yii2's parameterized query mechanisms.
    *   **Data Type Mismatches:** Risk reduced significantly.

*   **Currently Implemented:**
    *   Active Record is used for most database interactions.
    *   Basic model validation rules are in place.

*   **Missing Implementation:**
    *   A few older parts use `rawSql()` without Yii2's parameter binding.
    *   Input validation is not comprehensive; some fields lack Yii2 validation rules.

## Mitigation Strategy: [Secure Mass Assignment with Yii2 Scenarios](./mitigation_strategies/secure_mass_assignment_with_yii2_scenarios.md)

*   **Description:**
    1.  **Define Scenarios (Yii2 Models):** In each Active Record model, define scenarios for different operations (e.g., `create`, `update`).
    2.  **`safeAttributes` (Yii2 Models):** Within each scenario, specify the `safeAttributes` that are allowed to be mass-assigned using Yii2's scenario mechanism. Example (in the `User` model):
        ```php
        const SCENARIO_CREATE = 'create';
        const SCENARIO_UPDATE = 'update';

        public function scenarios()
        {
            $scenarios = parent::scenarios();
            $scenarios[self::SCENARIO_CREATE] = ['username', 'email', 'password'];
            $scenarios[self::SCENARIO_UPDATE] = ['username', 'email']; // Password not allowed
            return $scenarios;
        }
        ```
    3.  **Use `$model->load()` with Scenario (Yii2 Controller Logic):** When loading data from user input, *always* specify the scenario:
        ```php
        $model = new User();
        if ($model->load(Yii::$app->request->post(), self::SCENARIO_CREATE) && $model->save()) {
            // ...
        }
        ```
    4.  **Avoid Direct Assignment:** Do *not* bypass Yii2's scenario mechanism by using `$model->attributes = $_POST['ModelName'];`.        
    5. **Regular Review:** Periodically review model scenarios to ensure they are up-to-date.

*   **Threats Mitigated:**
    *   **Mass Assignment (Severity: Medium):** Yii2's scenario mechanism is the primary defense.

*   **Impact:**
    *   **Mass Assignment:** Risk reduced significantly (90%+) with proper use of Yii2 scenarios.

*   **Currently Implemented:**
    *   Scenarios are defined in some models.

*   **Missing Implementation:**
    *   Scenarios are not consistently defined across all models.
    *   Some controllers bypass Yii2's scenarios with direct assignment.

## Mitigation Strategy: [Disable Debug Mode and Configure Yii2's Error Handler](./mitigation_strategies/disable_debug_mode_and_configure_yii2's_error_handler.md)

*   **Description:**
    1.  **Production Settings (Yii2 Bootstrap):** In `web/index.php`, ensure `YII_DEBUG` is `false` and `YII_ENV` is `'prod'`:
        ```php
        defined('YII_DEBUG') or define('YII_DEBUG', false);
        defined('YII_ENV') or define('YII_ENV', 'prod');
        ```
    2.  **Error Handler Configuration (Yii2 Config):** In `config/web.php`, configure the `errorHandler` component:
        ```php
        'errorHandler' => [
            'errorAction' => 'site/error', // Use a custom Yii2 error action
        ],
        ```
    3.  **Custom Error Action (Yii2 Controller):** Create a custom error action (e.g., `controllers/SiteController.php`) to display a generic message *without* revealing sensitive details.  Use Yii2's logging:
        ```php
        public function actionError()
        {
            $exception = Yii::$app->errorHandler->exception;
            if ($exception !== null) {
                // Log using Yii2's logging framework
                Yii::error($exception->getMessage(), 'application');
                return $this->render('error', ['message' => 'An error occurred.']);
            }
        }
        ```
    4.  **Logging (Yii2 Config):** Configure Yii2's logging framework (`config/web.php`) to log errors to a secure file:
        ```php
        'log' => [
            'targets' => [
                [
                    'class' => 'yii\log\FileTarget',
                    'levels' => ['error', 'warning'],
                    'logFile' => '@runtime/logs/app.log', // Secure location
                ],
            ],
        ],
        ```

*   **Threats Mitigated:**
    *   **Information Disclosure (Severity: Medium):**  Yii2's debug mode and default error handling can expose sensitive information.

*   **Impact:**
    *   **Information Disclosure:** Risk significantly reduced (95%+) by disabling Yii2's debug mode and configuring the error handler.

*   **Currently Implemented:**
    *   `YII_DEBUG` and `YII_ENV` are set correctly.
    *   Basic Yii2 error logging is configured.

*   **Missing Implementation:**
    *   A custom Yii2 error action is not implemented; the default Yii2 error page is still shown (though without debug info).

## Mitigation Strategy: [Secure File Uploads with Yii2's `UploadedFile` and `FileValidator`](./mitigation_strategies/secure_file_uploads_with_yii2's__uploadedfile__and__filevalidator_.md)

*   **Description:**
    1.  **`UploadedFile` (Yii2):** Use Yii2's `UploadedFile` class to handle file uploads.
    2.  **`FileValidator` (Yii2 Model Rules):** Use Yii2's `FileValidator` in your model rules:
        ```php
        public function rules()
        {
            return [
                [['image'], 'file', 'skipOnEmpty' => false, 'extensions' => 'png, jpg, gif', 'maxSize' => 1024 * 1024 * 2, 'checkExtensionByMimeType' => true], // 2MB, check MIME type
            ];
        }
        ```
    3.  **Storage Outside Web Root (Using Yii2 Aliases):** Store files outside the web root using Yii2 aliases:
        ```php
        $uploadPath = Yii::getAlias('@app/uploads'); // Outside web root, defined using Yii2's alias system
        if (!is_dir($uploadPath)) {
            mkdir($uploadPath, 0777, true);
        }
        $model->image->saveAs($uploadPath . '/' . $uniqueFilename); // Use Yii2's saveAs() method
        ```
    4.  **Unique Filenames (with Yii2 Helpers):** Generate unique filenames (e.g., using `uniqid()` or a Yii2 helper function).

*   **Threats Mitigated:**
    *   **File Upload Vulnerabilities (Severity: High):** Yii2's `UploadedFile` and `FileValidator` provide the core mechanisms.
    *   **Directory Traversal (Severity: High):** Storing files outside the web root (using Yii2 aliases) is crucial.

*   **Impact:**
    *   **File Upload Vulnerabilities:** Risk significantly reduced (90%+) with proper use of Yii2's upload handling.
    *   **Directory Traversal:** Risk eliminated by using Yii2 aliases to store files outside the web root.

*   **Currently Implemented:**
    *   `UploadedFile` is used.
    *   Basic `FileValidator` rules are in place.

*   **Missing Implementation:**
    *   Files are stored *within* the web root (not using Yii2 aliases correctly).
    *   `checkExtensionByMimeType` is not set to `true` in the `FileValidator` rules.
    *   Unique filenames are not consistently generated using Yii2 helpers.

## Mitigation Strategy: [Secure Session Management with Yii2's Session Component](./mitigation_strategies/secure_session_management_with_yii2's_session_component.md)

*   **Description:**
    1.  **Session Component Configuration (Yii2 Config):** In `config/web.php`, configure the `session` component:
        ```php
        'session' => [
            'class' => 'yii\web\Session',
            'cookieParams' => [
                'httpOnly' => true,
                'secure' => true, // MUST be true if using HTTPS
                'path' => '/',
            ],
            'useStrictMode' => true,
            'useTransparentSessionID' => false,
            'timeout' => 1800, // 30 minutes
            // Consider using a different Yii2 session storage:
            // 'class' => 'yii\web\DbSession', // Yii2's database session
            // 'class' => 'yii\redis\Session', // Yii2's Redis session
        ],
        ```
    2.  **Session Regeneration (Yii2 Controller Logic):** Regenerate the session ID after login using Yii2's `regenerateID()`:
        ```php
        public function actionLogin()
        {
            // ... login logic ...
            if ($user->login()) {
                Yii::$app->session->regenerateID(); // Yii2's session regeneration
                return $this->goHome();
            }
        }
        ```
     3. **Logout (using Yii2's User component):** Ensure that the logout action properly destroys the session using Yii2's `logout()` method:
        ```php
         public function actionLogout()
        {
            Yii::$app->user->logout(); // Use Yii2's logout method
            return $this->goHome();
        }
        ```

*   **Threats Mitigated:**
    *   **Session Hijacking (Severity: High):** Yii2's session component settings (`httpOnly`, `secure`) are crucial.
    *   **Session Fixation (Severity: High):** Yii2's `regenerateID()` is the primary defense.

*   **Impact:**
    *   **Session Hijacking:** Risk significantly reduced with correct Yii2 session component settings.
    *   **Session Fixation:** Risk eliminated by using Yii2's `regenerateID()`.

*   **Currently Implemented:**
    *   `httpOnly` is set to `true` in the Yii2 session configuration.

*   **Missing Implementation:**
    *   `secure` is `false` (should be `true` with HTTPS).
    *   `useStrictMode` and `useTransparentSessionID` are not set in the Yii2 session configuration.
    *   Session ID is not regenerated after login using Yii2's `regenerateID()`.
    *   The default file-based session storage is used; consider Yii2's `DbSession` or `RedisSession`.

