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
 * Plugin library.
 *
 * @package auth_voidc
 * @author James McQuillan <james.mcquillan@remote-learner.net>
 * @author Lai Wei <lai.wei@enovation.ie>
 * @license http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 * @copyright (C) 2014 onwards Microsoft, Inc. (http://microsoft.com/)
 */

use auth_voidc\jwt;
use auth_voidc\utils;

// IdP types.
/**
 * Microsoft Entra ID identity provider type.
 */
const AUTH_VOIDC_IDP_TYPE_MICROSOFT_ENTRA_ID = 1;

/**
 * Microsoft Identity Platform identity provider type.
 */
const AUTH_VOIDC_IDP_TYPE_MICROSOFT_IDENTITY_PLATFORM = 2;

/**
 * Other identity provider type.
 */
const AUTH_VOIDC_IDP_TYPE_OTHER = 3;

// Microsoft Entra ID / Microsoft endpoint version.
/**
 * Unknown Microsoft endpoint version.
 */
const AUTH_VOIDC_MICROSOFT_ENDPOINT_VERSION_UNKNOWN = 0;

/**
 * Microsoft endpoint version 1.
 */
const AUTH_VOIDC_MICROSOFT_ENDPOINT_VERSION_1 = 1;

/**
 * Microsoft endpoint version 2.
 */
const AUTH_VOIDC_MICROSOFT_ENDPOINT_VERSION_2 = 2;

// OIDC application authentication method.
/**
 * OIDC application authentication method using secret.
 */
const AUTH_VOIDC_AUTH_METHOD_SECRET = 1;

/**
 * OIDC application authentication method using certificate.
 */
const AUTH_VOIDC_AUTH_METHOD_CERTIFICATE = 2;

// OIDC application auth certificate source.
/**
 * OIDC application authentication certificate source from text.
 */
const AUTH_VOIDC_AUTH_CERT_SOURCE_TEXT = 1;

/**
 * OIDC application authentication certificate source from file.
 */
const AUTH_VOIDC_AUTH_CERT_SOURCE_FILE = 2;

/**
 * Initialize custom icon for OIDC authentication.
 *
 * This function sets up a custom icon for the OIDC plugin by creating necessary directories
 * and copying the file into the specified location in Moodle's data directory.
 *
 * @param string $filefullname Full name of the custom icon file.
 * @return bool False if the file is missing or is a directory; void otherwise.
 */
function auth_voidc_initialize_customicon($filefullname) {
    global $CFG;

    $file = get_config('auth_voidc', 'customicon');
    $systemcontext = \context_system::instance();
    $fullpath = "/{$systemcontext->id}/auth_voidc/customicon/0{$file}";

    $fs = get_file_storage();
    if (!($file = $fs->get_file_by_hash(sha1($fullpath))) || $file->is_directory()) {
        return false;
    }
    $pixpluginsdir = 'pix_plugins/auth/oidc/0';
    $pixpluginsdirparts = explode('/', $pixpluginsdir);
    $curdir = $CFG->dataroot;
    foreach ($pixpluginsdirparts as $dir) {
        $curdir .= '/' . $dir;
        if (!file_exists($curdir)) {
            mkdir($curdir);
        }
    }

    if (file_exists($CFG->dataroot . '/pix_plugins/auth/oidc/0')) {
        $file->copy_content_to($CFG->dataroot . '/pix_plugins/auth/oidc/0/customicon.jpg');
        theme_reset_all_caches();
    }
}

/**
 * Check for connection abilities.
 *
 * @param int $userid Moodle user id to check permissions for.
 * @param string $mode Mode to check
 *                     'connect' to check for connect specific capability
 *                     'disconnect' to check for disconnect capability.
 *                     'both' to check for disconnect and connect capability.
 * @param boolean $require Use require_capability rather than has_capability.
 *
 * @return boolean True if has capability.
 */
function auth_voidc_connectioncapability($userid, $mode = 'connect', $require = false) {
    $check = 'has_capability';
    if ($require) {
        // If requiring the capability and user has manageconnection than checking connect and disconnect is not needed.
        $check = 'require_capability';
        if (has_capability('auth/oidc:manageconnection', \context_user::instance($userid), $userid)) {
            return true;
        }
    } else if ($check('auth/oidc:manageconnection', \context_user::instance($userid), $userid)) {
        return true;
    }

    $result = false;
    switch ($mode) {
        case "connect":
            $result = $check('auth/oidc:manageconnectionconnect', \context_user::instance($userid), $userid);
            break;
        case "disconnect":
            $result = $check('auth/oidc:manageconnectiondisconnect', \context_user::instance($userid), $userid);
            break;
        case "both":
            $result = $check('auth/oidc:manageconnectionconnect', \context_user::instance($userid), $userid);
            $result = $result && $check('auth/oidc:manageconnectiondisconnect', \context_user::instance($userid), $userid);
    }
    if ($require) {
        return true;
    }

    return $result;
}

/**
 * Determine if local_o365 plugins is installed.
 *
 * @return bool
 */
function auth_voidc_is_local_365_installed() {
    global $CFG, $DB;

    $dbmanager = $DB->get_manager();

    return file_exists($CFG->dirroot . '/local/o365/version.php') &&
        $DB->record_exists('config_plugins', ['plugin' => 'local_o365', 'name' => 'version']) &&
        $dbmanager->table_exists('local_o365_objects') &&
        $dbmanager->table_exists('local_o365_connections');
}

/**
 * Return details of all auth_voidc tokens having empty Moodle user IDs.
 *
 * @return array
 */
function auth_voidc_get_tokens_with_empty_ids() {
    global $DB;

    $emptyuseridtokens = [];

    $records = $DB->get_records('auth_voidc_token', ['userid' => '0']);

    foreach ($records as $record) {
        $item = new stdClass();
        $item->id = $record->id;
        $item->oidcusername = $record->oidcusername;
        $item->useriditifier = $record->useridentifier;
        $item->moodleusername = $record->username;
        $item->userid = 0;
        $item->oidcuniqueid = $record->oidcuniqid;
        $item->matchingstatus = get_string('unmatched', 'auth_voidc');
        $item->details = get_string('na', 'auth_voidc');
        $deletetokenurl = new moodle_url('/auth/oidc/cleanupoidctokens.php', ['id' => $record->id]);
        $item->action = html_writer::link($deletetokenurl, get_string('delete_token', 'auth_voidc'));

        $emptyuseridtokens[$record->id] = $item;
    }

    return $emptyuseridtokens;
}

/**
 * Return details of all auth_voidc tokens with matching Moodle user IDs, but mismatched usernames.
 *
 * @return array
 */
function auth_voidc_get_tokens_with_mismatched_usernames() {
    global $DB;

    $mismatchedtokens = [];

    $sql = 'SELECT tok.id AS id, tok.userid AS tokenuserid, tok.username AS tokenusername, tok.oidcusername AS oidcusername,
                   tok.useridentifier, tok.oidcuniqid as oidcuniqid, u.id AS muserid, u.username AS musername
              FROM {auth_voidc_token} tok
              JOIN {user} u ON u.id = tok.userid
             WHERE tok.userid != 0
               AND u.username != tok.username';
    $records = $DB->get_recordset_sql($sql);
    foreach ($records as $record) {
        $item = new stdClass();
        $item->id = $record->id;
        $item->oidcusername = $record->oidcusername;
        $item->useridentifier = $record->useridentifier;
        $item->userid = $record->muserid;
        $item->oidcuniqueid = $record->oidcuniqid;
        $item->matchingstatus = get_string('mismatched', 'auth_voidc');
        $item->details = get_string('mismatched_details', 'auth_voidc',
            ['tokenusername' => $record->tokenusername, 'moodleusername' => $record->musername]);
        $deletetokenurl = new moodle_url('/auth/oidc/cleanupoidctokens.php', ['id' => $record->id]);
        $item->action = html_writer::link($deletetokenurl, get_string('delete_token_and_reference', 'auth_voidc'));

        $mismatchedtokens[$record->id] = $item;
    }

    return $mismatchedtokens;
}

/**
 * Delete the auth_voidc token with the ID.
 *
 * @param int $tokenid
 */
function auth_voidc_delete_token(int $tokenid): void {
    global $DB;

    if (auth_voidc_is_local_365_installed()) {
        $sql = 'SELECT obj.id, obj.objectid, tok.token, u.id AS userid, u.email
                  FROM {local_o365_objects} obj
                  JOIN {auth_voidc_token} tok ON obj.o365name = tok.username
                  JOIN {user} u ON obj.moodleid = u.id
                 WHERE obj.type = :type AND tok.id = :tokenid';
        if ($objectrecord = $DB->get_record_sql($sql, ['type' => 'user', 'tokenid' => $tokenid], IGNORE_MULTIPLE)) {
            // Delete record from local_o365_objects.
            $DB->delete_records('local_o365_objects', ['id' => $objectrecord->id]);

            // Delete record from local_o365_token.
            $DB->delete_records('local_o365_token', ['user_id' => $objectrecord->userid]);

            // Delete record from local_o365_connections.
            $DB->delete_records_select('local_o365_connections', 'muserid = :userid OR LOWER(entraidupn) = :email',
                ['userid' => $objectrecord->userid, 'email' => $objectrecord->email]);
        }
    }

    $DB->delete_records('auth_voidc_token', ['id' => $tokenid]);
}

/**
 * Return the list of remote field options in field mapping.
 *
 * @return array
 */
function auth_voidc_get_remote_fields() {
    if (auth_voidc_is_local_365_installed()) {
        $remotefields = [
            '' => get_string('settings_fieldmap_feild_not_mapped', 'auth_voidc'),
            'bindingusernameclaim' => get_string('settings_fieldmap_field_bindingusernameclaim', 'auth_voidc'),
            'objectId' => get_string('settings_fieldmap_field_objectId', 'auth_voidc'),
            'userPrincipalName' => get_string('settings_fieldmap_field_userPrincipalName', 'auth_voidc'),
            'displayName' => get_string('settings_fieldmap_field_displayName', 'auth_voidc'),
            'givenName' => get_string('settings_fieldmap_field_givenName', 'auth_voidc'),
            'surname' => get_string('settings_fieldmap_field_surname', 'auth_voidc'),
            'mail' => get_string('settings_fieldmap_field_mail', 'auth_voidc'),
            'onPremisesSamAccountName' => get_string('settings_fieldmap_field_onPremisesSamAccountName', 'auth_voidc'),
            'streetAddress' => get_string('settings_fieldmap_field_streetAddress', 'auth_voidc'),
            'city' => get_string('settings_fieldmap_field_city', 'auth_voidc'),
            'postalCode' => get_string('settings_fieldmap_field_postalCode', 'auth_voidc'),
            'state' => get_string('settings_fieldmap_field_state', 'auth_voidc'),
            'country' => get_string('settings_fieldmap_field_country', 'auth_voidc'),
            'jobTitle' => get_string('settings_fieldmap_field_jobTitle', 'auth_voidc'),
            'department' => get_string('settings_fieldmap_field_department', 'auth_voidc'),
            'companyName' => get_string('settings_fieldmap_field_companyName', 'auth_voidc'),
            'preferredLanguage' => get_string('settings_fieldmap_field_preferredLanguage', 'auth_voidc'),
            'employeeId' => get_string('settings_fieldmap_field_employeeId', 'auth_voidc'),
            'businessPhones' => get_string('settings_fieldmap_field_businessPhones', 'auth_voidc'),
            'faxNumber' => get_string('settings_fieldmap_field_faxNumber', 'auth_voidc'),
            'mobilePhone' => get_string('settings_fieldmap_field_mobilePhone', 'auth_voidc'),
            'officeLocation' => get_string('settings_fieldmap_field_officeLocation', 'auth_voidc'),
            'preferredName' => get_string('settings_fieldmap_field_preferredName', 'auth_voidc'),
            'manager' => get_string('settings_fieldmap_field_manager', 'auth_voidc'),
            'manager_email' => get_string('settings_fieldmap_field_manager_email', 'auth_voidc'),
            'teams' => get_string('settings_fieldmap_field_teams', 'auth_voidc'),
            'groups' => get_string('settings_fieldmap_field_groups', 'auth_voidc'),
            'roles' => get_string('settings_fieldmap_field_roles', 'auth_voidc'),
        ];

        $order = 0;
        while ($order++ < 15) {
            $remotefields['extensionAttribute' . $order] = get_string('settings_fieldmap_field_extensionattribute', 'auth_voidc',
                $order);
        }

        // SDS profile sync.
        [$sdsprofilesyncenabled, $schoolid, $schoolname] = local_o365\feature\sds\utils::get_profile_sync_status_with_id_name();

        if ($sdsprofilesyncenabled) {
            $remotefields['sds_school_id'] = get_string('settings_fieldmap_field_sds_school_id', 'auth_voidc',
                get_config('local_o365', 'sdsprofilesync', $schoolid));
            $remotefields['sds_school_name'] = get_string('settings_fieldmap_field_sds_school_name', 'auth_voidc', $schoolname);
            $remotefields['sds_school_role'] = get_string('settings_fieldmap_field_sds_school_role', 'auth_voidc');
            $remotefields['sds_student_externalId'] = get_string('settings_fieldmap_field_sds_student_externalId', 'auth_voidc');
            $remotefields['sds_student_birthDate'] = get_string('settings_fieldmap_field_sds_student_birthDate', 'auth_voidc');
            $remotefields['sds_student_grade'] = get_string('settings_fieldmap_field_sds_student_grade', 'auth_voidc');
            $remotefields['sds_student_graduationYear'] = get_string('settings_fieldmap_field_sds_student_graduationYear',
                'auth_voidc');
            $remotefields['sds_student_studentNumber'] = get_string('settings_fieldmap_field_sds_student_studentNumber',
                'auth_voidc');
            $remotefields['sds_teacher_externalId'] = get_string('settings_fieldmap_field_sds_teacher_externalId', 'auth_voidc');
            $remotefields['sds_teacher_teacherNumber'] = get_string('settings_fieldmap_field_sds_teacher_teacherNumber',
                'auth_voidc');
        }
    } else {
        $remotefields = [
            '' => get_string('settings_fieldmap_feild_not_mapped', 'auth_voidc'),
            'bindingusernameclaim' => get_string('settings_fieldmap_field_bindingusernameclaim', 'auth_voidc'),
            'objectId' => get_string('settings_fieldmap_field_objectId', 'auth_voidc'),
            'userPrincipalName' => get_string('settings_fieldmap_field_userPrincipalName', 'auth_voidc'),
            'givenName' => get_string('settings_fieldmap_field_givenName', 'auth_voidc'),
            'surname' => get_string('settings_fieldmap_field_surname', 'auth_voidc'),
            'mail' => get_string('settings_fieldmap_field_mail', 'auth_voidc'),
        ];
    }

    return $remotefields;
}

/**
 * Return the list of available remote fields to map email field.
 *
 * @return array
 */
function auth_voidc_get_email_remote_fields() {
    $remotefields = [
        'mail' => get_string('settings_fieldmap_field_mail', 'auth_voidc'),
        'userPrincipalName' => get_string('settings_fieldmap_field_userPrincipalName', 'auth_voidc'),
    ];

    return $remotefields;
}

/**
 * Return the current field mapping settings in an array.
 *
 * @return array
 */
function auth_voidc_get_field_mappings() {
    $fieldmappings = [];

    $userfields = auth_voidc_get_all_user_fields();

    $authoidcconfig = get_config('auth_voidc');

    foreach ($userfields as $userfield) {
        $fieldmapsettingname = 'field_map_' . $userfield;
        if (property_exists($authoidcconfig, $fieldmapsettingname) && $authoidcconfig->$fieldmapsettingname) {
            $fieldsetting = [];
            $fieldsetting['field_map'] = $authoidcconfig->$fieldmapsettingname;

            $fieldlocksettingname = 'field_lock_' . $userfield;
            if (property_exists($authoidcconfig, $fieldlocksettingname)) {
                $fieldsetting['field_lock'] = $authoidcconfig->$fieldlocksettingname;
            } else {
                $fieldsetting['field_lock'] = 'unlocked';
            }

            $fieldupdatelocksettignname = 'field_updatelocal_' . $userfield;
            if (property_exists($authoidcconfig, $fieldupdatelocksettignname)) {
                $fieldsetting['update_local'] = $authoidcconfig->$fieldupdatelocksettignname;
            } else {
                $fieldsetting['update_local'] = 'always';
            }

            $fieldmappings[$userfield] = $fieldsetting;
        }
    }

    if (!array_key_exists('email', $fieldmappings)) {
        $fieldmappings['email'] = auth_voidc_apply_default_email_mapping();
    }

    if (!array_key_exists('firstname', $fieldmappings)) {
        $fieldmappings['firstname'] = auth_voidc_apply_default_firstname_mapping();
    }

    if (!array_key_exists('lastname', $fieldmappings)) {
        $fieldmappings['lastname'] = auth_voidc_apply_default_lastname_mapping();
    }

    return $fieldmappings;
}

/**
 * Apply default email mapping settings.
 *
 * @return array
 */
function auth_voidc_apply_default_email_mapping() {
    $existingsetting = get_config('auth_voidc', 'field_map_email');
    if ($existingsetting != 'mail') {
        add_to_config_log('field_map_email', $existingsetting, 'mail', 'auth_voidc');
    }
    set_config('field_map_email', 'mail', 'auth_voidc');

    $authoidcconfig = get_config('auth_voidc');

    $fieldsetting = [];
    $fieldsetting['field_map'] = 'mail';

    if (property_exists($authoidcconfig, 'field_lock_email')) {
        $fieldsetting['field_lock'] = $authoidcconfig->field_lock_email;
    } else {
        $fieldsetting['field_lock'] = 'unlocked';
    }

    if (property_exists($authoidcconfig, 'field_updatelocal_email')) {
        $fieldsetting['update_local'] = $authoidcconfig->field_updatelocal_email;
    } else {
        $fieldsetting['update_local'] = 'always';
    }

    return $fieldsetting;
}

/**
 * Apply default firstname mapping settings.
 *
 * @return array
 */
function auth_voidc_apply_default_firstname_mapping() {
    $existingsetting = get_config('auth_voidc', 'field_map_firstname');
    if ($existingsetting != 'firstname') {
        add_to_config_log('field_map_firstname', $existingsetting, 'firstname', 'auth_voidc');
    }
    set_config('field_map_firstname', 'givenName', 'auth_voidc');

    $authoidcconfig = get_config('auth_voidc');

    $fieldsetting = [];
    $fieldsetting['field_map'] = 'givenName';

    if (property_exists($authoidcconfig, 'field_lock_firstname')) {
        $fieldsetting['field_lock'] = $authoidcconfig->field_lock_firstname;
    } else {
        $fieldsetting['field_lock'] = 'unlocked';
    }

    if (property_exists($authoidcconfig, 'field_updatelocal_firstname')) {
        $fieldsetting['update_local'] = $authoidcconfig->field_updatelocal_firstname;
    } else {
        $fieldsetting['update_local'] = 'oncreate';
    }

    return $fieldsetting;
}

/**
 * Apply default lastname mapping settings.
 *
 * @return array
 */
function auth_voidc_apply_default_lastname_mapping() {
    $existingsetting = get_config('auth_voidc', 'field_map_lastname');
    if ($existingsetting != 'surname') {
        add_to_config_log('field_map_lastname', $existingsetting, 'surname', 'auth_voidc');
    }
    set_config('field_map_lastname', 'surname', 'auth_voidc');

    $authoidcconfig = get_config('auth_voidc');

    $fieldsetting = [];
    $fieldsetting['field_map'] = 'surname';

    if (property_exists($authoidcconfig, 'field_lock_lastname')) {
        $fieldsetting['field_lock'] = $authoidcconfig->field_lock_lastname;
    } else {
        $fieldsetting['field_lock'] = 'unlocked';
    }

    if (property_exists($authoidcconfig, 'field_updatelocal_lastname')) {
        $fieldsetting['update_local'] = $authoidcconfig->field_updatelocal_lastname;
    } else {
        $fieldsetting['update_local'] = 'oncreate';
    }

    return $fieldsetting;
}

/**
 * Helper function used to print mapping and locking for auth_voidc plugin on admin pages.
 *
 * @param stdclass $settings Moodle admin settings instance
 * @param string $auth authentication plugin shortname
 * @param array $userfields user profile fields
 * @param string $helptext help text to be displayed at top of form
 * @param boolean $mapremotefields Map fields or lock only.
 * @param boolean $updateremotefields Allow remote updates
 * @param array $customfields list of custom profile fields
 */
function auth_voidc_display_auth_lock_options($settings, $auth, $userfields, $helptext, $mapremotefields, $updateremotefields,
    $customfields = []) {
    global $DB;

    // Introductory explanation and help text.
    if ($mapremotefields) {
        $settings->add(new admin_setting_heading($auth.'/data_mapping', new lang_string('auth_data_mapping', 'auth'), $helptext));
    } else {
        $settings->add(new admin_setting_heading($auth.'/auth_fieldlocks', new lang_string('auth_fieldlocks', 'auth'), $helptext));
    }

    // Generate the list of options.
    $lockoptions = [
        'unlocked' => get_string('unlocked', 'auth'),
        'unlockedifempty' => get_string('unlockedifempty', 'auth'),
        'locked' => get_string('locked', 'auth'),
    ];

    if (auth_voidc_is_local_365_installed()) {
        $alwaystext = get_string('update_oncreate_and_onlogin_and_usersync', 'auth_voidc');
        $onlogintext = get_string('update_onlogin_and_usersync', 'auth_voidc');
    } else {
        $alwaystext = get_string('update_oncreate_and_onlogin', 'auth_voidc');
        $onlogintext = get_string('update_onlogin', 'auth');
    }
    $updatelocaloptions = [
        'always' => $alwaystext,
        'oncreate' => get_string('update_oncreate', 'auth'),
        'onlogin' => $onlogintext,
    ];

    $updateextoptions = [
        '0' => get_string('update_never', 'auth'),
        '1' => get_string('update_onupdate', 'auth'),
    ];

    // Generate the list of profile fields to allow updates / lock.
    if (!empty($customfields)) {
        $userfields = array_merge($userfields, $customfields);
        $customfieldname = $DB->get_records('user_info_field', null, '', 'shortname, name');
    }

    $remotefields = auth_voidc_get_remote_fields();
    $emailremotefields = auth_voidc_get_email_remote_fields();

    foreach ($userfields as $field) {
        // Define the fieldname we display to the  user.
        // this includes special handling for some profile fields.
        $fieldname = $field;
        $fieldnametoolong = false;
        if ($fieldname === 'lang') {
            $fieldname = get_string('language');
        } else if (!empty($customfields) && in_array($field, $customfields)) {
            // If custom field then pick name from database.
            $fieldshortname = str_replace('profile_field_', '', $fieldname);
            $fieldname = $customfieldname[$fieldshortname]->name;
            if (core_text::strlen($fieldshortname) > 67) {
                // If custom profile field name is longer than 67 characters we will not be able to store the setting
                // such as 'field_updateremote_profile_field_NOTSOSHORTSHORTNAME' in the database because the character
                // limit for the setting name is 100.
                $fieldnametoolong = true;
            }
        } else if ($fieldname == 'url') {
            $fieldname = get_string('webpage');
        } else {
            $fieldname = get_string($fieldname);
        }

        // Generate the list of fields / mappings.
        if ($fieldnametoolong) {
            // Display a message that the field can not be mapped because it's too long.
            $url = new moodle_url('/user/profile/index.php');
            $a = (object)['fieldname' => s($fieldname), 'shortname' => s($field), 'charlimit' => 67, 'link' => $url->out()];
            $settings->add(new admin_setting_heading($auth.'/field_not_mapped_'.sha1($field), '',
                get_string('cannotmapfield', 'auth', $a)));
        } else if ($mapremotefields) {
            // We are mapping to a remote field here.
            // Mapping.
            if ($field == 'email') {
                $settings->add(new admin_setting_configselect("auth_voidc/field_map_{$field}",
                    get_string('auth_fieldmapping', 'auth', $fieldname), '', null, $emailremotefields));
            } else {
                $settings->add(new admin_setting_configselect("auth_voidc/field_map_{$field}",
                    get_string('auth_fieldmapping', 'auth', $fieldname), '', null, $remotefields));
            }

            // Update local.
            $settings->add(new admin_setting_configselect("auth_{$auth}/field_updatelocal_{$field}",
                get_string('auth_updatelocalfield', 'auth', $fieldname), '', 'always', $updatelocaloptions));

            // Update remote.
            if ($updateremotefields) {
                $settings->add(new admin_setting_configselect("auth_{$auth}/field_updateremote_{$field}",
                    get_string('auth_updateremotefield', 'auth', $fieldname), '', 0, $updateextoptions));
            }

            // Lock fields.
            $settings->add(new admin_setting_configselect("auth_{$auth}/field_lock_{$field}",
                get_string('auth_fieldlockfield', 'auth', $fieldname), '', 'unlocked', $lockoptions));
        } else {
            // Lock fields Only.
            $settings->add(new admin_setting_configselect("auth_{$auth}/field_lock_{$field}",
                get_string('auth_fieldlockfield', 'auth', $fieldname), '', 'unlocked', $lockoptions));
        }
    }
}

/**
 * Return all user profile field names in an array.
 *
 * @return array|string[]|null
 */
function auth_voidc_get_all_user_fields() {
    $authplugin = get_auth_plugin('oidc');
    $userfields = $authplugin->userfields;
    $userfields = array_merge($userfields, $authplugin->get_custom_user_profile_fields());

    return $userfields;
}

/**
 * Determine the endpoint version of the given Microsoft Entra ID / Microsoft authorization or token endpoint.
 *
 * @param string $endpoint The URL of the endpoint to be checked.
 * @return int The version of the Microsoft endpoint (1 or 2) or unknown.
 */
function auth_voidc_determine_endpoint_version(string $endpoint) {
    $endpointversion = AUTH_VOIDC_MICROSOFT_ENDPOINT_VERSION_UNKNOWN;

    if (strpos($endpoint, 'https://login.microsoftonline.com/') === 0) {
        if (strpos($endpoint, 'oauth2/v2.0/') !== false) {
            $endpointversion = AUTH_VOIDC_MICROSOFT_ENDPOINT_VERSION_2;
        } else if (strpos($endpoint, 'oauth2') !== false) {
            $endpointversion = AUTH_VOIDC_MICROSOFT_ENDPOINT_VERSION_1;
        }
    }

    return $endpointversion;
}

/**
 * Return formatted form element name to be used by configuration variables in custom forms.
 *
 * @param string $stringid
 * @return string
 */
function auth_voidc_config_name_in_form(string $stringid) {
    $formatedformitemname = get_string($stringid, 'auth_voidc') .
        html_writer::span('auth_voidc | ' . $stringid, 'form-shortname d-block small text-muted');

    return $formatedformitemname;
}

/**
 * Check if the auth_voidc plugin has been configured with the minimum settings for the SSO integration to work.
 *
 * @return bool
 */
function auth_voidc_is_setup_complete() {
    $pluginconfig = get_config('auth_voidc');
    if (empty($pluginconfig->clientid) || empty($pluginconfig->idptype) || empty($pluginconfig->clientauthmethod)) {
        return false;
    }

    switch ($pluginconfig->clientauthmethod) {
        case AUTH_VOIDC_AUTH_METHOD_SECRET:
            if (empty($pluginconfig->clientsecret)) {
                return false;
            }
            break;
        case AUTH_VOIDC_AUTH_METHOD_CERTIFICATE:
            if (!isset($pluginconfig->clientcertsource)) {
                $existingclientcertsource = get_config('auth_voidc', 'clientcertsource');
                if ($existingclientcertsource != AUTH_VOIDC_AUTH_CERT_SOURCE_TEXT) {
                    add_to_config_log('clientcertsource', $existingclientcertsource, AUTH_VOIDC_AUTH_CERT_SOURCE_TEXT, 'auth_voidc');
                }
                set_config('clientcertsource', AUTH_VOIDC_AUTH_CERT_SOURCE_TEXT, 'auth_voidc');
                $pluginconfig->clientcertsource = AUTH_VOIDC_AUTH_CERT_SOURCE_TEXT;
            }
            switch ($pluginconfig->clientcertsource) {
                case AUTH_VOIDC_AUTH_CERT_SOURCE_FILE:
                    if (!utils::get_certpath() || !utils::get_keypath()) {
                        return false;
                    }
                    break;
                case AUTH_VOIDC_AUTH_CERT_SOURCE_TEXT:
                    if (empty($pluginconfig->clientcert) || empty($pluginconfig->clientprivatekey)) {
                        return false;
                    }
                    break;
            }
            break;
    }

    if (empty($pluginconfig->authendpoint) || empty($pluginconfig->tokenendpoint)) {
        return false;
    }

    return true;
}

/**
 * Return the name of the configured IdP type.
 *
 * @return lang_string|string
 */
function auth_voidc_get_idp_type_name() {
    $idptypename = '';

    switch (get_config('auth_voidc', 'idptype')) {
        case AUTH_VOIDC_IDP_TYPE_MICROSOFT_ENTRA_ID:
            $idptypename = get_string('idp_type_microsoft_entra_id', 'auth_voidc');
            break;
        case AUTH_VOIDC_IDP_TYPE_MICROSOFT_IDENTITY_PLATFORM:
            $idptypename = get_string('idp_type_microsoft_identity_platform', 'auth_voidc');
            break;
        case AUTH_VOIDC_IDP_TYPE_OTHER:
            $idptypename = get_string('idp_type_other', 'auth_voidc');
            break;
    }

    return $idptypename;
}

/**
 * Return the name of the configured authentication method.
 *
 * @return lang_string|string
 */
function auth_voidc_get_client_auth_method_name() {
    $authmethodname = '';

    switch (get_config('auth_voidc', 'clientauthmethod')) {
        case AUTH_VOIDC_AUTH_METHOD_SECRET:
            $authmethodname = get_string('auth_method_secret', 'auth_voidc');
            break;
        case AUTH_VOIDC_AUTH_METHOD_CERTIFICATE:
            $authmethodname = get_string('auth_method_certificate', 'auth_voidc');
            break;
    }

    return $authmethodname;
}

/**
 * Return the name of the configured binding username claim.
 *
 * @return string
 */
function auth_voidc_get_binding_username_claim(): string {
    $bindingusernameclaim = get_config('auth_voidc', 'bindingusernameclaim');

    if (empty($bindingusernameclaim)) {
        $bindingusernameclaim = 'auto';
    } else if ($bindingusernameclaim === 'custom') {
        $bindingusernameclaim = get_config('auth_voidc', 'customclaimname');
    } else if (!in_array($bindingusernameclaim, ['auto', 'preferred_username', 'email', 'upn', 'unique_name', 'sub', 'oid',
        'samaccountname'])) {
        $bindingusernameclaim = 'auto';
    }

    return $bindingusernameclaim;
}

/**
 * Return the claims that presents in the existing tokens.
 *
 * @return array
 * @throws moodle_exception
 */
function auth_voidc_get_existing_claims(): array {
    global $DB;

    $sql = 'SELECT *
              FROM {auth_voidc_token}
          ORDER BY expiry DESC';
    $tokenrecord = $DB->get_record_sql($sql, null, IGNORE_MULTIPLE);

    $tokenclaims = [];

    if ($tokenrecord) {
        $excludedclaims = ['appid', 'appidacr', 'app_displayname', 'ipaddr', 'scp', 'tenant_region_scope', 'ver', 'aud', 'iss',
            'iat', 'nbf', 'exp', 'idtyp', 'plantf', 'xms_tcdt', 'xms_tdbr', 'amr', 'nonce', 'tid', 'acct', 'acr', 'signin_state',
            'wids'];

        foreach (['idtoken', 'token'] as $tokenkey) {
            $decodedtoken = jwt::decode($tokenrecord->$tokenkey);
            if (is_array($decodedtoken) && count($decodedtoken) > 1) {
                foreach ($decodedtoken[1] as $claim => $value) {
                    if (!in_array($claim, $excludedclaims) && (is_string($value) || is_numeric($value)) &&
                        !in_array($claim, $tokenclaims)) {
                        $tokenclaims[] = $claim;
                    }
                }
            }
        }

        asort($tokenclaims);
    }

    return $tokenclaims;
}

/**
 * Return if the user sync feature in local_o365 plugin is enabled.
 *
 * @return bool|void
 */
function auth_voidc_is_user_sync_enabled() {
    global $CFG;

    if (auth_voidc_is_local_365_installed()) {
        require_once($CFG->dirroot . '/local/o365/classes/feature/usersync/main.php');
        return local_o365\feature\usersync\main::is_enabled();
    }

    return false;
}
