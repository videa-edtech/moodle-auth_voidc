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
 * Manage binding username claim form.
 *
 * @package auth_voidc
 * @author Lai Wei <lai.wei@enovation.ie>
 * @license http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 * @copyright (C) 2024 onwards Videa Edtech Ltd.
 */

namespace auth_voidc\form;

use moodle_exception;
use moodleform;

defined('MOODLE_INTERNAL') || die();

require_once($CFG->dirroot . '/auth/voidc/lib.php');

/**
 * Class bindingusernameclaim represents the form on the binding username claim configuration page.
 */
class binding_username_claim extends moodleform {
    /**
     * Option for setting a non-Microsoft IdP.
     */
    const OPTION_SET_NON_MS_IDP = 1;

    /**
     * Option for setting a Microsoft IdP without user sync.
     */
    const OPTION_SET_MS_NO_USER_SYNC = 2;

    /**
     * Option for setting a Microsoft IdP with user sync enabled.
     */
    const OPTION_SET_MS_WITH_USER_SYNC = 3;

    /** @var int */
    private $optionset = 0;

    /**
     * Form definition.
     *
     * @return void
     */
    protected function definition() {
        $mform =& $this->_form;

        // Binding username claim.
        $this->optionset = self::OPTION_SET_NON_MS_IDP;
        $descriptionidentifier = 'binding_username_claim_help_non_ms';
        $bindingusernameoptions = [
            'auto'               => get_string('binding_username_auto', 'auth_voidc'),
            'preferred_username' => 'preferred_username',
            'email'              => 'email',
            'sub'                => 'sub',
            'custom'             => get_string('binding_username_custom', 'auth_voidc'),
        ];

        $mform->addElement(
                'select',
                'bindingusernameclaim',
                auth_voidc_config_name_in_form('bindingusernameclaim'),
                $bindingusernameoptions
        );
        $mform->setDefault('bindingusernameclaim', 'auto');
        $mform->addElement('static', 'bindingusernameclaim_description', '', get_string($descriptionidentifier, 'auth_voidc'));

        // Custom claim name.
        if ($this->optionset == self::OPTION_SET_NON_MS_IDP || $this->optionset == self::OPTION_SET_MS_NO_USER_SYNC) {
            $mform->addElement('text', 'customclaimname', auth_voidc_config_name_in_form('customclaimname'), ['size' => 40]);
            $mform->setType('customclaimname', PARAM_TEXT);
            $mform->disabledIf('customclaimname', 'bindingusernameclaim', 'neq', 'custom'); // Enable only if "Custom" is selected.

            // Custom claim name description.
            $mform->addElement('static', 'customclaimname_description', '', get_string('customclaimname_description', 'auth_voidc'));
        }

        // Save buttons.
        $this->add_action_buttons();
    }
}
