<?php
// This file is part of Moodle - http://moodle.org/
//
// Moodle is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Moodle is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with Moodle.  If not, see <http://www.gnu.org/licenses/>.

/**
 * Form shown to a voidc user whose derived username collides with an existing
 * Moodle account, letting them pick a unique username to finish signing up.
 *
 * @package auth_voidc
 * @license http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 * @copyright (C) 2024 onwards Videa Edtech Ltd.
 */

namespace auth_voidc\form;

defined('MOODLE_INTERNAL') || die();

require_once($CFG->dirroot . '/lib/formslib.php');

/**
 * Choose-a-new-username form for voidc signup collisions.
 */
class choose_username extends \moodleform {
    /**
     * Form definition.
     */
    protected function definition() {
        $mform =& $this->_form;

        $collided = $this->_customdata['collided'] ?? '';
        $suggested = $this->_customdata['suggested'] ?? '';

        $mform->addElement('html', \html_writer::div(
            get_string('choose_username_description', 'auth_voidc', $collided),
            'mb-3'
        ));

        $mform->addElement('text', 'username', get_string('choose_username_label', 'auth_voidc'),
            ['autocomplete' => 'username', 'autofocus' => 'autofocus']);
        $mform->setType('username', PARAM_USERNAME);
        $mform->addRule('username', get_string('required'), 'required', null, 'client');
        $mform->addHelpButton('username', 'choose_username_label', 'auth_voidc');
        if ($suggested !== '') {
            $mform->setDefault('username', $suggested);
        }

        $this->add_action_buttons(true, get_string('choose_username_submit', 'auth_voidc'));
    }

    /**
     * Server-side validation: require a valid, unique, non-colliding username.
     *
     * @param array $data
     * @param array $files
     * @return array
     */
    public function validation($data, $files) {
        global $CFG, $DB;

        $errors = parent::validation($data, $files);

        $raw = isset($data['username']) ? trim((string) $data['username']) : '';
        if ($raw === '') {
            $errors['username'] = get_string('choose_username_required', 'auth_voidc');
            return $errors;
        }

        $username = \core_text::strtolower($raw);

        // Enforce Moodle's username character rules. clean_param rejects invalid
        // characters silently, so compare cleaned vs raw to detect them.
        $cleaned = clean_param($username, PARAM_USERNAME);
        if ($cleaned === '' || $cleaned !== $username) {
            $errors['username'] = get_string('choose_username_invalid', 'auth_voidc');
            return $errors;
        }

        // Reject the original colliding username
        $collided = $this->_customdata['collided'] ?? '';
        if ($collided !== '' && $username === \core_text::strtolower($collided)) {
            $errors['username'] = get_string('choose_username_same_as_collided', 'auth_voidc');
            return $errors;
        }

        // Uniqueness recheck - another user could have taken this name between
        // page render and submit.
        if ($DB->record_exists('user', ['username' => $username, 'mnethostid' => $CFG->mnet_localhost_id])) {
            $errors['username'] = get_string('choose_username_taken', 'auth_voidc');
            return $errors;
        }

        return $errors;
    }
}
