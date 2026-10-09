<!-- Copyright (c) 2026 Battelle Energy Alliance, LLC. All rights reserved. -->
<footer class="malcolm-footer" role="contentinfo">
  <div class="container malcolm-footer-content">
    <p class="text-muted small">
      <a href="https://github.com/cisagov/Malcolm/releases">Malcolm<?php
        $version = getenv('MALCOLM_VERSION');
        if ($version) {
          echo ' ' . htmlspecialchars($version, ENT_QUOTES, 'UTF-8');
        }
      ?></a>
      &copy; 2026 Battelle Energy Alliance, LLC.
    </p>
    <nav aria-label="Malcolm resources">
      <a href="/">Home</a>
      <a href="/readme/">Documentation</a>
      <a href="/mapi/ready">Service Readiness</a>
      <a href="https://github.com/cisagov/Malcolm">GitHub</a>
    </nav>
  </div>
</footer>
</body>
</html>
