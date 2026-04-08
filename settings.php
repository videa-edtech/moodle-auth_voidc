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
 * Plugin settings.
 *
 * @package auth_voidc
 * @author James McQuillan <james.mcquillan@remote-learner.net>
 * @author Lai Wei <lai.wei@enovation.ie>
 * @license http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 * @copyright (C) 2024 onwards Videa Edtech Ltd.
 */

defined('MOODLE_INTERNAL') || die();

use auth_voidc\adminsetting\auth_voidc_admin_setting_iconselect;
use auth_voidc\adminsetting\auth_voidc_admin_setting_loginflow;
use auth_voidc\adminsetting\auth_voidc_admin_setting_redirecturi;
use auth_voidc\utils;

require_once($CFG->dirroot . '/auth/voidc/lib.php');

if ($hassiteconfig) {
    // Add folder for OIDC settings.
    $oidcfolder = new admin_category('oidcfolder', get_string('pluginname', 'auth_voidc'));
    $ADMIN->add('authsettings', $oidcfolder);

    // Application configuration page.
    $ADMIN->add('oidcfolder', new admin_externalpage('auth_voidc_application', get_string('settings_page_application', 'auth_voidc'),
        new moodle_url('/auth/oidc/manageapplication.php')));


    // Other settings page and its settings.
    $settings = new admin_settingpage($section, get_string('settings_page_other_settings', 'auth_voidc'));

    // Basic heading.
    $settings->add(new admin_setting_heading('auth_voidc/basic_heading', get_string('heading_basic', 'auth_voidc'),
        get_string('heading_basic_desc', 'auth_voidc')));

    // Redirect URI.
    $settings->add(new auth_voidc_admin_setting_redirecturi('auth_voidc/redirecturi',
        get_string('cfg_redirecturi_key', 'auth_voidc'), get_string('cfg_redirecturi_desc', 'auth_voidc'), utils::get_redirecturl()));

    // Link to authentication options.
    $authenticationconfigurationurl = new moodle_url('/auth/oidc/manageapplication.php');
    $settings->add(new admin_setting_description('auth_voidc/authenticationlink',
        get_string('settings_page_application', 'auth_voidc'),
        get_string('cfg_authenticationlink_desc', 'auth_voidc', $authenticationconfigurationurl->out())));

    // Additional options heading.
    $settings->add(new admin_setting_heading('auth_voidc/additional_options_heading',
        get_string('heading_additional_options', 'auth_voidc'), get_string('heading_additional_options_desc', 'auth_voidc')));

    // Force redirect.
    $settings->add(new admin_setting_configcheckbox('auth_voidc/forceredirect',
        get_string('cfg_forceredirect_key', 'auth_voidc'), get_string('cfg_forceredirect_desc', 'auth_voidc'), 0));

    // Silent login mode.
    $forceloginconfigurl = new moodle_url('/admin/settings.php', ['section' => 'sitepolicies']);
    $settings->add(new admin_setting_configcheckbox('auth_voidc/silentloginmode',
        get_string('cfg_silentloginmode_key', 'auth_voidc'),
        get_string('cfg_silentloginmode_desc', 'auth_voidc', $forceloginconfigurl->out(false)), 0));

    // Auto-append.
    $settings->add(new admin_setting_configtext('auth_voidc/autoappend',
        get_string('cfg_autoappend_key', 'auth_voidc'), get_string('cfg_autoappend_desc', 'auth_voidc'), '', PARAM_TEXT));

    // Domain hint.
    $settings->add(new admin_setting_configtext('auth_voidc/domainhint',
        get_string('cfg_domainhint_key', 'auth_voidc'), get_string('cfg_domainhint_desc', 'auth_voidc'), '' , PARAM_TEXT));

    // Login flow.
    $settings->add(new auth_voidc_admin_setting_loginflow('auth_voidc/loginflow',
        get_string('cfg_loginflow_key', 'auth_voidc'), '', 'authcode'));

    // User restrictions heading.
    $settings->add(new admin_setting_heading('auth_voidc/user_restrictions_heading',
        get_string('heading_user_restrictions', 'auth_voidc'), get_string('heading_user_restrictions_desc', 'auth_voidc')));

    // User restrictions.
    $settings->add(new admin_setting_configtextarea('auth_voidc/userrestrictions',
        get_string('cfg_userrestrictions_key', 'auth_voidc'), get_string('cfg_userrestrictions_desc', 'auth_voidc'), '', PARAM_TEXT));

    // User restrictions case sensitivity.
    $settings->add(new admin_setting_configcheckbox('auth_voidc/userrestrictionscasesensitive',
        get_string('cfg_userrestrictionscasesensitive_key', 'auth_voidc'),
        get_string('cfg_userrestrictionscasesensitive_desc', 'auth_voidc'), '1'));

    // Sign out integration heading.
    $settings->add(new admin_setting_heading('auth_voidc/sign_out_heading',
        get_string('heading_sign_out', 'auth_voidc'), get_string('heading_sign_out_desc', 'auth_voidc')));

    // Single sign out from Moodle to IdP.
    $settings->add(new admin_setting_configcheckbox('auth_voidc/single_sign_off',
        get_string('cfg_signoffintegration_key', 'auth_voidc'),
        get_string('cfg_signoffintegration_desc', 'auth_voidc', $CFG->wwwroot), '0'));

    // Single sign out from Moodle for keycloak
    $oidcservices = [
        'default' => 'default',
        'keycloak' => 'keycloak',
    ];
    $settings->add(new admin_setting_configselect('auth_voidc/oidc_service',
        get_string('cfg_oidcservice_key', 'auth_voidc'),
        get_string('cfg_oidcservice_desc', 'auth_voidc', $CFG->wwwroot), 'ddefault', $oidcservices));

    // IdP logout endpoint.
    $settings->add(new admin_setting_configtext('auth_voidc/logouturi',
        get_string('cfg_logoutendpoint_key', 'auth_voidc'), get_string('cfg_logoutendpoint_desc', 'auth_voidc'),
        '', PARAM_URL));

    // Front channel logout URL.
    $settings->add(new auth_voidc_admin_setting_redirecturi('auth_voidc/logoutendpoint',
        get_string('cfg_frontchannellogouturl_key', 'auth_voidc'), get_string('cfg_frontchannellogouturl_desc', 'auth_voidc'),
        utils::get_frontchannellogouturl()));

    // Display heading.
    $settings->add(new admin_setting_heading('auth_voidc/display_heading',
        get_string('heading_display', 'auth_voidc'), get_string('heading_display_desc', 'auth_voidc')));

    // Provider Name (opname).
    $settings->add(new admin_setting_configtext('auth_voidc/opname',
        get_string('cfg_opname_key', 'auth_voidc'), get_string('cfg_opname_desc', 'auth_voidc'),
        get_string('pluginname', 'auth_voidc'), PARAM_TEXT));

    // Icon.
    $icons = [
        [
            'pix' => 'o365',
            'alt' => new lang_string('cfg_iconalt_o365', 'auth_voidc'),
            'component' => 'auth_voidc',
        ],
        [
            'pix' => 't/locked',
            'alt' => new lang_string('cfg_iconalt_locked', 'auth_voidc'),
            'component' => 'moodle',
        ],
        [
            'pix' => 't/lock',
            'alt' => new lang_string('cfg_iconalt_lock', 'auth_voidc'),
            'component' => 'moodle',
        ],
        [
            'pix' => 't/go',
            'alt' => new lang_string('cfg_iconalt_go', 'auth_voidc'),
            'component' => 'moodle',
        ],
        [
            'pix' => 't/stop',
            'alt' => new lang_string('cfg_iconalt_stop', 'auth_voidc'),
            'component' => 'moodle',
        ],
        [
            'pix' => 't/user',
            'alt' => new lang_string('cfg_iconalt_user', 'auth_voidc'),
            'component' => 'moodle',
        ],
        [
            'pix' => 'u/user35',
            'alt' => new lang_string('cfg_iconalt_user2', 'auth_voidc'),
            'component' => 'moodle',
        ],
        [
            'pix' => 'i/permissions',
            'alt' => new lang_string('cfg_iconalt_key', 'auth_voidc'),
            'component' => 'moodle',
        ],
        [
            'pix' => 'i/cohort',
            'alt' => new lang_string('cfg_iconalt_group', 'auth_voidc'),
            'component' => 'moodle',
        ],
        [
            'pix' => 'i/groups',
            'alt' => new lang_string('cfg_iconalt_group2', 'auth_voidc'),
            'component' => 'moodle',
        ],
        [
            'pix' => 'i/mnethost',
            'alt' => new lang_string('cfg_iconalt_mnet', 'auth_voidc'),
            'component' => 'moodle',
        ],
        [
            'pix' => 'i/permissionlock',
            'alt' => new lang_string('cfg_iconalt_userlock', 'auth_voidc'),
            'component' => 'moodle',
        ],
        [
            'pix' => 't/more',
            'alt' => new lang_string('cfg_iconalt_plus', 'auth_voidc'),
            'component' => 'moodle',
        ],
        [
            'pix' => 't/approve',
            'alt' => new lang_string('cfg_iconalt_check', 'auth_voidc'),
            'component' => 'moodle',
        ],
        [
            'pix' => 't/right',
            'alt' => new lang_string('cfg_iconalt_rightarrow', 'auth_voidc'),
            'component' => 'moodle',
        ],
    ];
    $settings->add(new auth_voidc_admin_setting_iconselect('auth_voidc/icon',
        get_string('cfg_icon_key', 'auth_voidc'), get_string('cfg_icon_desc', 'auth_voidc'), 'auth_voidc:o365', $icons));

    // Custom icon.
    $configkey = new lang_string('cfg_customicon_key', 'auth_voidc');
    $configdesc = new lang_string('cfg_customicon_desc', 'auth_voidc');
    $customiconsetting = new admin_setting_configstoredfile('auth_voidc/customicon',
        get_string('cfg_customicon_key', 'auth_voidc'), get_string('cfg_customicon_desc', 'auth_voidc'), 'customicon', 0,
        ['accepted_types' => ['.png', '.jpg', '.ico'], 'maxbytes' => get_max_upload_file_size()]);
    $customiconsetting->set_updatedcallback('auth_voidc_initialize_customicon');
    $settings->add($customiconsetting);

    // Debugging heading.
    $settings->add(new admin_setting_heading('auth_voidc/debugging_heading',
        get_string('heading_debugging', 'auth_voidc'), get_string('heading_debugging_desc', 'auth_voidc')));

    // Record debugging messages.
    $settings->add(new admin_setting_configcheckbox('auth_voidc/debugmode',
        get_string('cfg_debugmode_key', 'auth_voidc'), get_string('cfg_debugmode_desc', 'auth_voidc'), '0'));

    $ADMIN->add('oidcfolder', $settings);

    // Cleanup OIDC tokens page.
    $ADMIN->add('oidcfolder', new admin_externalpage('auth_voidc_cleanup_oidc_tokens',
        get_string('settings_page_cleanup_oidc_tokens', 'auth_voidc'), new moodle_url('/auth/oidc/cleanupoidctokens.php')));

    // Other settings page and its settings.
    $fieldmappingspage = new admin_settingpage('auth_voidc_field_mapping', get_string('settings_page_field_mapping', 'auth_voidc'));
    $ADMIN->add('oidcfolder', $fieldmappingspage);

    // Display locking / mapping of profile fields.
    $authplugin = get_auth_plugin('oidc');
    auth_voidc_display_auth_lock_options($fieldmappingspage, $authplugin->authtype, $authplugin->userfields,
        get_string('cfg_field_mapping_desc', 'auth_voidc'), true, false, $authplugin->get_custom_user_profile_fields());
}

$settings = null;
