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
 * Form for adding or editing an OIDC client (IdP).
 *
 * @package auth_voidc
 * @license http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 * @copyright (C) 2024 onwards Videa Edtech Ltd.
 */

namespace auth_voidc\form;

use moodleform;

defined('MOODLE_INTERNAL') || die();

require_once($CFG->dirroot . '/auth/voidc/lib.php');

/**
 * Add/edit form for an auth_voidc_clients row.
 */
class clientedit extends moodleform {
    /**
     * Form definition.
     *
     * @return void
     */
    protected function definition() {
        $mform =& $this->_form;

        // Hidden id (0 for new).
        $mform->addElement('hidden', 'id', 0);
        $mform->setType('id', PARAM_INT);

        // Basic settings header.
        $mform->addElement('header', 'basic', get_string('settings_section_basic', 'auth_voidc'));
        $mform->setExpanded('basic');

        // Display name.
        $mform->addElement('text', 'name', get_string('client_field_name', 'auth_voidc'), ['size' => 40]);
        $mform->setType('name', PARAM_TEXT);
        $mform->addRule('name', null, 'required', null, 'client');
        $mform->addElement('static', 'name_help', '', get_string('client_field_name_help', 'auth_voidc'));

        // Client ID.
        $mform->addElement('text', 'clientid', get_string('clientid', 'auth_voidc'), ['size' => 40]);
        $mform->setType('clientid', PARAM_TEXT);
        $mform->addRule('clientid', null, 'required', null, 'client');
        $mform->addElement('static', 'clientid_help', '', get_string('clientid_help', 'auth_voidc'));

        // Authentication header.
        $mform->addElement('header', 'authentication', get_string('settings_section_authentication', 'auth_voidc'));
        $mform->setExpanded('authentication');

        // Client secret.
        $mform->addElement('passwordunmask', 'clientsecret', get_string('clientsecret', 'auth_voidc'), ['size' => 60]);
        $mform->setType('clientsecret', PARAM_RAW_TRIMMED);
        $mform->addElement('static', 'clientsecret_help', '', get_string('clientsecret_help', 'auth_voidc'));

        // Endpoints header.
        $mform->addElement('header', 'endpoints', get_string('settings_section_endpoints', 'auth_voidc'));
        $mform->setExpanded('endpoints');

        // Authorization endpoint.
        $mform->addElement('text', 'authendpoint', get_string('authendpoint', 'auth_voidc'), ['size' => 60]);
        $mform->setType('authendpoint', PARAM_URL);
        $mform->addRule('authendpoint', null, 'required', null, 'client');
        $mform->addElement('static', 'authendpoint_help', '', get_string('authendpoint_help', 'auth_voidc'));

        // Token endpoint.
        $mform->addElement('text', 'tokenendpoint', get_string('tokenendpoint', 'auth_voidc'), ['size' => 60]);
        $mform->setType('tokenendpoint', PARAM_URL);
        $mform->addRule('tokenendpoint', null, 'required', null, 'client');
        $mform->addElement('static', 'tokenendpoint_help', '', get_string('tokenendpoint_help', 'auth_voidc'));

        // Logout endpoint (optional).
        $mform->addElement('text', 'logoutendpoint', get_string('logoutendpoint', 'auth_voidc'), ['size' => 60]);
        $mform->setType('logoutendpoint', PARAM_URL);
        $mform->addElement('static', 'logoutendpoint_help', '', get_string('logoutendpoint_help', 'auth_voidc'));

        // Other parameters header.
        $mform->addElement('header', 'otherparams', get_string('settings_section_other_params', 'auth_voidc'));
        $mform->setExpanded('otherparams');

        // Resource.
        $mform->addElement('text', 'oidcresource', get_string('oidcresource', 'auth_voidc'), ['size' => 60]);
        $mform->setType('oidcresource', PARAM_TEXT);
        $mform->addElement('static', 'oidcresource_help', '', get_string('oidcresource_help', 'auth_voidc'));

        // Scope.
        $mform->addElement('text', 'oidcscope', get_string('oidcscope', 'auth_voidc'), ['size' => 60]);
        $mform->setType('oidcscope', PARAM_TEXT);
        $mform->setDefault('oidcscope', 'openid profile email');
        $mform->addElement('static', 'oidcscope_help', '', get_string('oidcscope_help', 'auth_voidc'));

        // Binding username claim.
        $bindingoptions = [
            'auto'               => get_string('binding_username_auto', 'auth_voidc'),
            'preferred_username' => 'preferred_username',
            'email'              => 'email',
            'sub'                => 'sub',
            'custom'             => get_string('binding_username_custom', 'auth_voidc'),
        ];
        $mform->addElement('select', 'bindingusernameclaim',
            get_string('bindingusernameclaim', 'auth_voidc'), $bindingoptions);
        $mform->setDefault('bindingusernameclaim', 'auto');
        $mform->addElement('static', 'bindingusernameclaim_description', '',
            get_string('binding_username_claim_help_non_ms', 'auth_voidc'));

        $mform->addElement('text', 'customclaimname', get_string('customclaimname', 'auth_voidc'), ['size' => 40]);
        $mform->setType('customclaimname', PARAM_TEXT);
        $mform->disabledIf('customclaimname', 'bindingusernameclaim', 'neq', 'custom');
        $mform->addElement('static', 'customclaimname_description', '',
            get_string('customclaimname_description', 'auth_voidc'));

        // Display header (icon upload).
        $mform->addElement('header', 'display', get_string('settings_section_display', 'auth_voidc'));
        $mform->setExpanded('display');

        $mform->addElement('filemanager', 'icon_filemanager',
            get_string('client_field_icon', 'auth_voidc'), null,
            auth_voidc_client_icon_filemanager_options());
        $mform->addElement('static', 'icon_help', '', get_string('client_field_icon_help', 'auth_voidc'));

        // Save buttons.
        $this->add_action_buttons();
    }

    /**
     * Form validation.
     *
     * @param array $data
     * @param array $files
     * @return array
     */
    public function validation($data, $files) {
        $errors = parent::validation($data, $files);

        if (empty(trim($data['name'] ?? ''))) {
            $errors['name'] = get_string('required');
        }

        // Require a secret only when creating a new client.
        // On edit, leaving the secret blank means "keep the existing one" — handled in the page.
        if (empty($data['id']) && empty(trim($data['clientsecret'] ?? ''))) {
            $errors['clientsecret'] = get_string('error_empty_client_secret', 'auth_voidc');
        }

        return $errors;
    }
}