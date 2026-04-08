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
 * OIDC application configuration page.
 *
 * @package auth_voidc
 * @author Lai Wei <lai.wei@enovation.ie>
 * @license http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 * @copyright (C) 2024 onwards Videa Edtech Ltd.
 */

use auth_voidc\form\application;

require_once(dirname(__FILE__) . '/../../config.php');
require_once($CFG->libdir . '/adminlib.php');
require_once($CFG->dirroot . '/auth/voidc/lib.php');

require_login();

$url = new moodle_url('/auth/voidc/manageapplication.php');
$PAGE->set_url($url);
$PAGE->set_context(context_system::instance());
$PAGE->set_pagelayout('admin');
$PAGE->set_heading(get_string('settings_page_application', 'auth_voidc'));
$PAGE->set_title(get_string('settings_page_application', 'auth_voidc'));

admin_externalpage_setup('auth_voidc_application');

require_admin();

$oidcconfig = get_config('auth_voidc');

$form = new application(null, ['oidcconfig' => $oidcconfig]);

$formdata = [];
foreach (['clientid', 'clientsecret', 'authendpoint', 'tokenendpoint', 'oidcresource', 'oidcscope',
    'bindingusernameclaim', 'customclaimname'] as $field) {
    if (isset($oidcconfig->$field)) {
        $formdata[$field] = $oidcconfig->$field;
    }
}

$form->set_data($formdata);

if ($form->is_cancelled()) {
    redirect($url);
} else if ($fromform = $form->get_data()) {
    // Prepare config settings to save.
    $configstosave = ['clientid', 'clientsecret', 'authendpoint', 'tokenendpoint', 'oidcresource', 'oidcscope'];

    // Save config settings.
    $settingschanged = false;
    foreach ($configstosave as $config) {
        $existingsetting = get_config('auth_voidc', $config);
        if ($fromform->$config != $existingsetting) {
            add_to_config_log($config, $existingsetting, $fromform->$config, 'auth_voidc');
            set_config($config, $fromform->$config, 'auth_voidc');
            $settingschanged = true;
        }
    }

    if ($settingschanged) {
        redirect($url, get_string('application_updated', 'auth_voidc'));
    } else {
        redirect($url, get_string('application_not_changed', 'auth_voidc'));
    }
}

echo $OUTPUT->header();

$form->display();

echo $OUTPUT->footer();