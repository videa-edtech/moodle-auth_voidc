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
 * Client (IdP) management page — list view with row actions.
 *
 * @package auth_voidc
 * @license http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 * @copyright (C) 2024 onwards Videa Edtech Ltd.
 */

require_once(dirname(__FILE__) . '/../../config.php');
require_once($CFG->libdir . '/adminlib.php');
require_once($CFG->dirroot . '/auth/voidc/lib.php');

require_login();
admin_externalpage_setup('auth_voidc_application');
require_admin();

$url = new moodle_url('/auth/voidc/manageapplication.php');
$PAGE->set_url($url);
$PAGE->set_context(context_system::instance());
$PAGE->set_pagelayout('admin');
$PAGE->set_heading(get_string('settings_page_application', 'auth_voidc'));
$PAGE->set_title(get_string('settings_page_application', 'auth_voidc'));

// Handle row actions (enable/disable/delete/move). All require sesskey.
$action = optional_param('action', '', PARAM_ALPHA);
$clientid = optional_param('id', 0, PARAM_INT);

if ($action !== '' && $clientid > 0) {
    require_sesskey();
    $client = auth_voidc_get_client($clientid);
    if (!$client) {
        redirect($url, get_string('client_not_found', 'auth_voidc'),
            null, \core\output\notification::NOTIFY_ERROR);
    }

    switch ($action) {
        case 'enable':
            auth_voidc_set_client_enabled($clientid, true);
            redirect($url, get_string('client_enabled', 'auth_voidc', s($client->name)));

        case 'disable':
            auth_voidc_set_client_enabled($clientid, false);
            redirect($url, get_string('client_disabled', 'auth_voidc', s($client->name)));

        case 'moveup':
            auth_voidc_move_client($clientid, 'up');
            redirect($url);

        case 'movedown':
            auth_voidc_move_client($clientid, 'down');
            redirect($url);

        case 'delete':
            $confirm = optional_param('confirm', 0, PARAM_BOOL);
            if (!$confirm) {
                echo $OUTPUT->header();
                echo $OUTPUT->confirm(
                    get_string('client_delete_confirm', 'auth_voidc', s($client->name)),
                    new moodle_url($url, ['action' => 'delete', 'id' => $clientid,
                        'confirm' => 1, 'sesskey' => sesskey()]),
                    $url
                );
                echo $OUTPUT->footer();
                exit;
            }
            auth_voidc_delete_client($clientid);
            redirect($url, get_string('client_deleted', 'auth_voidc', s($client->name)));
    }
}

$clients = auth_voidc_get_all_clients();

echo $OUTPUT->header();
echo $OUTPUT->heading(get_string('client_list_heading', 'auth_voidc'));
echo html_writer::tag('p', get_string('client_list_intro', 'auth_voidc'));

// Add new button.
$addurl = new moodle_url('/auth/voidc/editclient.php');
echo html_writer::start_div('voidc-client-toolbar');
echo html_writer::link($addurl,
    $OUTPUT->pix_icon('t/add', '') . ' ' . get_string('client_add', 'auth_voidc'),
    ['class' => 'btn btn-primary']);
echo html_writer::end_div();

echo html_writer::start_tag('table', ['class' => 'voidc-client-list table']);

// Header.
echo html_writer::start_tag('thead');
echo html_writer::start_tag('tr');
echo html_writer::tag('th', '', ['class' => 'voidc-client-icon']);
echo html_writer::tag('th', get_string('client_col_name', 'auth_voidc'));
echo html_writer::tag('th', get_string('client_col_clientid', 'auth_voidc'));
echo html_writer::tag('th', get_string('client_col_authendpoint', 'auth_voidc'));
echo html_writer::tag('th', get_string('client_col_status', 'auth_voidc'));
echo html_writer::tag('th', get_string('client_col_actions', 'auth_voidc'),
    ['class' => 'voidc-client-actions']);
echo html_writer::end_tag('tr');
echo html_writer::end_tag('thead');

echo html_writer::start_tag('tbody');

if (empty($clients)) {
    echo html_writer::start_tag('tr', ['class' => 'voidc-client-empty']);
    echo html_writer::tag('td', get_string('client_list_empty', 'auth_voidc'),
        ['colspan' => 6]);
    echo html_writer::end_tag('tr');
} else {
    $clientsarr = array_values($clients);
    $count = count($clientsarr);
    foreach ($clientsarr as $idx => $client) {
        echo html_writer::start_tag('tr');

        // Icon.
        $iconurl = auth_voidc_get_client_icon_url((int) $client->id);
        if ($iconurl) {
            $iconhtml = html_writer::empty_tag('img', [
                'src' => $iconurl->out(false),
                'alt' => s($client->name),
            ]);
        } else {
            $iconhtml = $OUTPUT->pix_icon('i/mnethost', s($client->name));
        }
        echo html_writer::tag('td', $iconhtml, ['class' => 'voidc-client-icon']);

        // Name.
        echo html_writer::tag('td', html_writer::tag('strong', s($client->name)));

        // Client ID.
        echo html_writer::tag('td', html_writer::tag('code', s($client->clientid)));

        // Auth endpoint (truncated).
        $endpoint = s($client->authendpoint);
        $shortened = (strlen($endpoint) > 60) ? substr($endpoint, 0, 57) . '…' : $endpoint;
        echo html_writer::tag('td',
            html_writer::tag('span', $shortened, ['title' => $endpoint, 'class' => 'text-muted small']));

        // Status pill.
        if ($client->enabled) {
            $status = html_writer::tag('span', get_string('client_status_enabled', 'auth_voidc'),
                ['class' => 'voidc-client-status enabled']);
        } else {
            $status = html_writer::tag('span', get_string('client_status_disabled', 'auth_voidc'),
                ['class' => 'voidc-client-status disabled']);
        }
        echo html_writer::tag('td', $status);

        // Actions.
        $actions = '';

        // Move up / down.
        if ($idx > 0) {
            $actions .= $OUTPUT->action_icon(
                new moodle_url($url, ['action' => 'moveup', 'id' => $client->id, 'sesskey' => sesskey()]),
                new pix_icon('t/up', get_string('moveup'))
            );
        } else {
            $actions .= $OUTPUT->spacer(['class' => 'iconsmall']);
        }
        if ($idx < $count - 1) {
            $actions .= $OUTPUT->action_icon(
                new moodle_url($url, ['action' => 'movedown', 'id' => $client->id, 'sesskey' => sesskey()]),
                new pix_icon('t/down', get_string('movedown'))
            );
        } else {
            $actions .= $OUTPUT->spacer(['class' => 'iconsmall']);
        }

        // Enable / disable toggle.
        if ($client->enabled) {
            $actions .= $OUTPUT->action_icon(
                new moodle_url($url, ['action' => 'disable', 'id' => $client->id, 'sesskey' => sesskey()]),
                new pix_icon('t/hide', get_string('disable'))
            );
        } else {
            $actions .= $OUTPUT->action_icon(
                new moodle_url($url, ['action' => 'enable', 'id' => $client->id, 'sesskey' => sesskey()]),
                new pix_icon('t/show', get_string('enable'))
            );
        }

        // Edit.
        $actions .= $OUTPUT->action_icon(
            new moodle_url('/auth/voidc/editclient.php', ['id' => $client->id]),
            new pix_icon('t/edit', get_string('edit'))
        );

        // Delete.
        $actions .= $OUTPUT->action_icon(
            new moodle_url($url, ['action' => 'delete', 'id' => $client->id, 'sesskey' => sesskey()]),
            new pix_icon('t/delete', get_string('delete'))
        );

        echo html_writer::tag('td', $actions, ['class' => 'voidc-client-actions']);
        echo html_writer::end_tag('tr');
    }
}

echo html_writer::end_tag('tbody');
echo html_writer::end_tag('table');

echo $OUTPUT->footer();