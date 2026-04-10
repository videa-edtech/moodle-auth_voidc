<?php
  // auth/voidc/tests/form_choose_username_test.php

  namespace auth_voidc;

  defined('MOODLE_INTERNAL') || die();

  global $CFG;
  require_once($CFG->dirroot . '/auth/voidc/classes/form/choose_username.php');

  /**
   * Unit tests for the choose_username form validation.
   *
   * @package auth_voidc
   * @covers \auth_voidc\form\choose_username
   */
  final class form_choose_username_test extends \advanced_testcase {

      /**
       * Run the form's validation() directly with a crafted data array.
       *
       * moodleform::validation is protected, so reach it via reflection. This
       * lets us test the rules without driving the whole form lifecycle.
       *
       * @param array $data  the posted form data
       * @param string $collided  the colliding username stashed in customdata
       * @return array  validation errors keyed by field
       */
      private function run_validation(array $data, string $collided = 'apple'): array {
          $form = new \auth_voidc\form\choose_username(null, [
              'collided' => $collided,
              'suggested' => $collided . '.idpb',
          ]);

          $ref = new \ReflectionMethod($form, 'validation');
          $ref->setAccessible(true);
          return (array) $ref->invoke($form, $data, []);
      }

      /**
       * Case 4: invalid / malformed usernames must be rejected.
       */
      public function test_rejects_invalid_usernames(): void {
          $this->resetAfterTest(true);

          // Empty string -> "required".
          $errors = $this->run_validation(['username' => '']);
          $this->assertArrayHasKey('username', $errors);

          // Whitespace-only -> trimmed to empty -> "required".
          $errors = $this->run_validation(['username' => '   ']);
          $this->assertArrayHasKey('username', $errors);

          // Uppercase -> lowercased internally, but 'APPLE' == 'apple' after
          // strtolower, which is the collided name. Use a distinct uppercase
          // input that doesn't collide so we exercise the char rule itself.
          $errors = $this->run_validation(['username' => 'Banana With Spaces']);
          $this->assertArrayHasKey('username', $errors);

          // Special characters.
          $errors = $this->run_validation(['username' => 'banana!']);
          $this->assertArrayHasKey('username', $errors);

          // Another invalid char. Note: PARAM_USERNAME permits '@' (email-style
          // usernames are legal in Moodle), so use something actually stripped.
          $errors = $this->run_validation(['username' => 'ban#na']);
          $this->assertArrayHasKey('username', $errors);
      }

      /**
       * Case 5: picking the colliding username itself must be rejected.
       */
      public function test_rejects_collided_username(): void {
          $this->resetAfterTest(true);

          $errors = $this->run_validation(['username' => 'apple'], 'apple');
          $this->assertArrayHasKey('username', $errors);
          $this->assertSame(
              get_string('choose_username_same_as_collided', 'auth_voidc'),
              $errors['username']
          );

          // Case-insensitive: 'APPLE' must also be rejected as the collided one.
          $errors = $this->run_validation(['username' => 'APPLE'], 'apple');
          $this->assertArrayHasKey('username', $errors);
          $this->assertSame(
              get_string('choose_username_same_as_collided', 'auth_voidc'),
              $errors['username']
          );
      }

      /**
       * Case 6: picking a name that belongs to another existing Moodle user
       * must be rejected with the "taken" error.
       */
      public function test_rejects_taken_username(): void {
          $this->resetAfterTest(true);

          // Create a real user via the data generator - this inserts into the
          // phpu_user table, which the uniqueness check queries.
          $existing = $this->getDataGenerator()->create_user(['username' => 'cherry']);

          $errors = $this->run_validation(['username' => 'cherry']);
          $this->assertArrayHasKey('username', $errors);
          $this->assertSame(
              get_string('choose_username_taken', 'auth_voidc'),
              $errors['username']
          );
      }

      /**
       * Happy path: a valid, unique, non-colliding username passes.
       */
      public function test_accepts_valid_username(): void {
          $this->resetAfterTest(true);

          $errors = $this->run_validation(['username' => 'apple.idpb'], 'apple');
          $this->assertArrayNotHasKey('username', $errors);
      }
  }
