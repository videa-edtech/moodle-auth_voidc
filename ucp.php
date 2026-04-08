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
 * User control panel page.
 *
 * @package auth_voidc
 * @author James McQuillan <james.mcquillan@remote-learner.net>
 * @license http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 * @copyright (C) 2014 onwards Microsoft, Inc. (http://microsoft.com/)
 */

require_once(__DIR__.'/../../config.php');
require_once(__DIR__.'/auth.php');
require_once(__DIR__.'/lib.php');

require_login();

$action = optional_param('action', null, PARAM_TEXT);

$oidctoken = $DB->get_record('auth_voidc_token', ['userid' => $USER->id]);
$oidcconnected = (!empty($oidctoken)) ? true : false;

$oidcloginconnected = ($USER->auth === 'oidc') ? true : false;

if (!is_enabled_auth('oidc')) {
    throw new moodle_exception('erroroidcnotenabled', 'auth_voidc');
}

if (!empty($action)) {
    if ($action === 'connectlogin' && $oidcloginconnected === false) {
        // Use authorization request login flow to connect existing users.
        auth_voidc_connectioncapability($USER->id, 'connect', true);
        $auth = new \auth_voidc\loginflow\authcode;
        $auth->set_httpclient(new \auth_voidc\httpclient());
        $auth->initiateauthrequest();
    } else if ($action === 'disconnectlogin' && $oidcloginconnected === true) {
        if (is_enabled_auth('manual') === true) {
            auth_voidc_connectioncapability($USER->id, 'disconnect', true);
            $auth = new \auth_plugin_oidc;
            $auth->set_httpclient(new \auth_voidc\httpclient());
            $auth->disconnect();
        }
    } else {
        throw new moodle_exception('errorucpinvalidaction', 'auth_voidc');
    }
} else {
    $PAGE->set_url('/auth/oidc/ucp.php');
    $usercontext = \context_user::instance($USER->id);
    $PAGE->set_context(\context_system::instance());
    $PAGE->set_pagelayout('standard');
    $USER->editing = false;
    $authconfig = get_config('auth_voidc');
    $opname = (!empty($authconfig->opname)) ? $authconfig->opname : get_string('pluginname', 'auth_voidc');

    $ucptitle = get_string('ucp_title', 'auth_voidc', $opname);
    $PAGE->navbar->add($ucptitle, $PAGE->url);
    $PAGE->set_title($ucptitle);

    echo $OUTPUT->header();
    echo \html_writer::tag('h2', $ucptitle);
    echo get_string('ucp_general_intro', 'auth_voidc', $opname);
    echo '<br /><br />';

    if (optional_param('o365accountconnected', null, PARAM_TEXT) == 'true') {
        echo \html_writer::start_div('connectionstatus alert alert-error');
        echo \html_writer::tag('h5', get_string('ucp_o365accountconnected', 'auth_voidc'));
        echo \html_writer::end_div();
    }

    // Login status.
    echo \html_writer::start_div('auth_voidc_ucp_indicator');
    echo \html_writer::tag('h4', get_string('ucp_login_status', 'auth_voidc', $opname));
    if ($oidcloginconnected === true) {
        echo \html_writer::tag('h4', get_string('ucp_status_enabled', 'auth_voidc'), ['class' => 'notifysuccess']);
        if (is_enabled_auth('manual') === true) {
            if (auth_voidc_connectioncapability($USER->id, 'disconnect')) {
                $connectlinkuri = new \moodle_url('/auth/oidc/ucp.php', ['action' => 'disconnectlogin']);
                $strdisconnect = get_string('ucp_login_stop', 'auth_voidc', $opname);
                $linkhtml = \html_writer::link($connectlinkuri, $strdisconnect);
                echo \html_writer::tag('h5', $linkhtml);
                echo \html_writer::span(get_string('ucp_login_stop_desc', 'auth_voidc', $opname));
            }
        }
    } else {
        echo \html_writer::tag('h4', get_string('ucp_status_disabled', 'auth_voidc'), ['class' => 'notifyproblem']);
        if (auth_voidc_connectioncapability($USER->id, 'connect')) {
            $connectlinkuri = new \moodle_url('/auth/oidc/ucp.php', ['action' => 'connectlogin']);
            $linkhtml = \html_writer::link($connectlinkuri, get_string('ucp_login_start', 'auth_voidc', $opname));
            echo \html_writer::tag('h5', $linkhtml);
            echo \html_writer::span(get_string('ucp_login_start_desc', 'auth_voidc', $opname));
        }
    }
    echo \html_writer::end_div();

    echo $OUTPUT->footer();
}
