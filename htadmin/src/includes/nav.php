<?php
// Copyright (c) 2026 Battelle Energy Alliance, LLC. All rights reserved.
// Shared Malcolm navigation for the embedded htadmin account manager.
?>
<nav class="navbar navbar-default malcolm-navigation" aria-label="Account management navigation">
  <div class="container malcolm-navigation-content">
    <div class="navbar-header">
      <a class="navbar-brand malcolm-brand" href="/" aria-label="Malcolm home">
        <img src="malcolm-icon.svg" alt="Malcolm" class="malcolm-brand-logo">
        <span>Malcolm <small>Local Account Management</small></span>
      </a>
    </div>
    <ul class="nav navbar-nav navbar-right malcolm-navigation-links">
      <?php if (check_admin_login()): ?>
        <li><a href="htadmin.php">Accounts</a></li>
        <li><a href="admin_logout.php">Logout</a></li>
      <?php else: ?>
        <li><a href="admin_login.php">Administrator Login</a></li>
        <li><a href="selfservice.php">Account Self Service</a></li>
      <?php endif; ?>
    </ul>
  </div>
</nav>
