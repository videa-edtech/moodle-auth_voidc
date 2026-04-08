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
 * Authentication and endpoints configuration form.
 *
 * @package auth_voidc
 * @author Lai Wei <lai.wei@enovation.ie>
 * @license http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 * @copyright (C) 2024 onwards Videa Edtech Ltd.
 */

namespace auth_voidc\form;

use moodleform;

defined('MOODLE_INTERNAL') || die();

require_once($CFG->dirroot . '/auth/voidc/lib.php');

/**
 * Class authentication_and_endpoints represents the form on the authentication and endpoints configuration page.
 */
class application extends moodleform {
    /**
     * Form definition.
     *
     * @return void
     */
    protected function definition() {
        $mform =& $this->_form;

        // Basic settings header.
        $mform->addElement('header', 'basic', get_string('settings_section_basic', 'auth_voidc'));

        // Client ID.
        $mform->addElement('text', 'clientid', auth_voidc_config_name_in_form('clientid'), ['size' => 40]);
        $mform->setType('clientid', PARAM_TEXT);
        $mform->addElement('static', 'clientid_help', '', get_string('clientid_help', 'auth_voidc'));
        $mform->addRule('clientid', null, 'required', null, 'client');

        // Authentication header.
        $mform->addElement('header', 'authentication', get_string('settings_section_authentication', 'auth_voidc'));
        $mform->setExpanded('authentication');

        // Secret.
        $mform->addElement('text', 'clientsecret', auth_voidc_config_name_in_form('clientsecret'), ['size' => 60]);
        $mform->setType('clientsecret', PARAM_TEXT);
        $mform->addElement('static', 'clientsecret_help', '', get_string('clientsecret_help', 'auth_voidc'));

        // Endpoints header.
        $mform->addElement('header', 'endpoints', get_string('settings_section_endpoints', 'auth_voidc'));
        $mform->setExpanded('endpoints');

        // Authorization endpoint.
        $mform->addElement('text', 'authendpoint', auth_voidc_config_name_in_form('authendpoint'), ['size' => 60]);
        $mform->setType('authendpoint', PARAM_URL);
        $mform->addElement('static', 'authendpoint_help', '', get_string('authendpoint_help', 'auth_voidc'));
        $mform->addRule('authendpoint', null, 'required', null, 'client');

        // Token endpoint.
        $mform->addElement('text', 'tokenendpoint', auth_voidc_config_name_in_form('tokenendpoint'), ['size' => 60]);
        $mform->setType('tokenendpoint', PARAM_URL);
        $mform->addElement('static', 'tokenendpoint_help', '', get_string('tokenendpoint_help', 'auth_voidc'));
        $mform->addRule('tokenendpoint', null, 'required', null, 'client');

        // Other parameters header.
        $mform->addElement('header', 'otherparams', get_string('settings_section_other_params', 'auth_voidc'));
        $mform->setExpanded('otherparams');

        // Resource.
        $mform->addElement('text', 'oidcresource', auth_voidc_config_name_in_form('oidcresource'), ['size' => 60]);
        $mform->setType('oidcresource', PARAM_TEXT);
        $mform->addElement('static', 'oidcresource_help', '', get_string('oidcresource_help', 'auth_voidc'));

        // Scope.
        $mform->addElement('text', 'oidcscope', auth_voidc_config_name_in_form('oidcscope'), ['size' => 60]);
        $mform->setType('oidcscope', PARAM_TEXT);
        $mform->setDefault('oidcscope', 'openid profile email');
        $mform->addElement('static', 'oidcscope_help', '', get_string('oidcscope_help', 'auth_voidc'));

        // Save buttons.
        $this->add_action_buttons();
    }

    /**
     * Additional validate rules.
     *
     * @param array $data Submitted data for validation.
     * @param array $files Uploaded files for validation.
     * @return array An array of validation errors, if any.
     */
    public function validation($data, $files) {
        $errors = parent::validation($data, $files);

        // Validate client secret.
        if (empty(trim($data['clientsecret']))) {
            $errors['clientsecret'] = get_string('error_empty_client_secret', 'auth_voidc');
        }

        // Validate oidcresource.
        if (empty(trim($data['oidcresource']))) {
            $errors['oidcresource'] = get_string('error_empty_oidcresource', 'auth_voidc');
        }

        return $errors;
    }
}