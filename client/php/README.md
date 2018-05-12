# DICOM PHP Client

Work in progress

## Getting Started

```
composer install
```

## Usage

Update `examples/index.php` to change host/port as appropriate.

```
$ php examples/index.php

class stdClass#27 (4) {
  public $method =>
  string(10) "CreateUser"
  public $username =>
  string(5) "danny"
  public $usercreated =>
  string(5) "false"
  public $existingusername =>
  string(4) "true"
}

class stdClass#17 (3) {
  public $method =>
  string(13) "CheckUsername"
  public $username =>
  string(5) "danny"
  public $existingusername =>
  string(4) "true"
}

class stdClass#30 (3) {
  public $method =>
  string(9) "CheckUser"
  public $username =>
  string(5) "danny"
  public $credentialcheck =>
  string(4) "true"
}
```

