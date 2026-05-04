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
 * Add or edit an OIDC client (IdP).
 *
 * @package auth_voidc
 * @license http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 * @copyright (C) 2024 onwards Videa Edtech Ltd.
 */

use auth_voidc\form\clientedit;

require_once(dirname(__FILE__) . '/../../config.php');
require_once($CFG->libdir . '/adminlib.php');
require_once($CFG->dirroot . '/auth/voidc/lib.php');

require_login();
admin_externalpage_setup('auth_voidc_application');
require_admin();

$id = optional_param('id', 0, PARAM_INT);

$listurl = new moodle_url('/auth/voidc/manageapplication.php');
$pageurl = new moodle_url('/auth/voidc/editclient.php', $id ? ['id' => $id] : []);

$PAGE->set_url($pageurl);
$PAGE->set_context(context_system::instance());
$PAGE->set_pagelayout('admin');

$existing = null;
if ($id) {
    $existing = auth_voidc_get_client($id);
    if (!$existing) {
        redirect($listurl, get_string('client_not_found', 'auth_voidc'),
            null, \core\output\notification::NOTIFY_ERROR);
    }
    $heading = get_string('client_edit_heading', 'auth_voidc', s($existing->name));
} else {
    $heading = get_string('client_add_heading', 'auth_voidc');
}

$PAGE->set_title($heading);
$PAGE->set_heading($heading);
$PAGE->navbar->add(get_string('client_add_heading', 'auth_voidc'), $pageurl);

$context = context_system::instance();
$fileoptions = auth_voidc_client_icon_filemanager_options();
$departmentoptions = [0 => get_string('choosedots')];
$departments = $DB->get_records('vloom_wp_departments', null, 'name ASC', 'id,name,parent_id');
$childrenbyparent = [];
foreach ($departments as $department) {
    $parentid = empty($department->parent_id) ? 0 : (int)$department->parent_id;
    $childrenbyparent[$parentid][] = $department;
}

$visited = [];
$appenddepartmentoptions = function(int $parentid, int $level) use (&$appenddepartmentoptions, &$departmentoptions, &$childrenbyparent, &$visited): void {
    if (empty($childrenbyparent[$parentid])) {
        return;
    }
    foreach ($childrenbyparent[$parentid] as $department) {
        $departmentid = (int)$department->id;
        if (isset($visited[$departmentid])) {
            continue;
        }
        $visited[$departmentid] = true;
        $departmentoptions[$departmentid] = str_repeat('— ', $level) . format_string($department->name);
        $appenddepartmentoptions($departmentid, $level + 1);
    }
};
$appenddepartmentoptions(0, 0);

foreach ($departments as $department) {
    $departmentid = (int)$department->id;
    if (!isset($visited[$departmentid])) {
        $departmentoptions[$departmentid] = format_string($department->name);
    }
}
$groupoptions = [0 => get_string('none')];
$groups = $DB->get_records('vloom_permission_groups', ['enabled' => 1], 'name ASC', 'id, name, shortname');
foreach ($groups as $group) {
    $groupoptions[$group->id] = $group->name . ' (' . $group->shortname . ')';
}

$form = new clientedit($pageurl->out(false), [
    'departmentoptions' => $departmentoptions,
    'groupoptions' => $groupoptions,
]);
// Build draft area for the icon filemanager.
$draftdata = $existing ? (array) $existing : ['id' => 0];
if ($existing) {
    // Don't prefill the secret value into the form — show empty (means "keep existing").
    $draftdata['clientsecret'] = '';
}
$draftitemid = 0;
file_prepare_draft_area($draftitemid, $context->id, 'auth_voidc',
    AUTH_VOIDC_ICON_FILEAREA, $existing ? (int) $existing->id : 0,
    ['subdirs' => 0, 'maxfiles' => 1]);
$draftdata['icon_filemanager'] = $draftitemid;
$form->set_data($draftdata);

if ($form->is_cancelled()) {
    redirect($listurl);
} else if ($data = $form->get_data()) {
    if ($id) {
        // On edit, blank secret means "keep current value".
        if (empty(trim((string) ($data->clientsecret ?? '')))) {
            $data->clientsecret = $existing->clientsecret;
        }
        auth_voidc_update_client($id, $data);
        file_save_draft_area_files($data->icon_filemanager, $context->id, 'auth_voidc',
            AUTH_VOIDC_ICON_FILEAREA, $id, ['subdirs' => 0, 'maxfiles' => 1]);
        redirect($listurl, get_string('client_updated', 'auth_voidc', s($data->name)));
    } else {
        $newid = auth_voidc_create_client($data);
        file_save_draft_area_files($data->icon_filemanager, $context->id, 'auth_voidc',
            AUTH_VOIDC_ICON_FILEAREA, $newid, ['subdirs' => 0, 'maxfiles' => 1]);
        redirect($listurl, get_string('client_created', 'auth_voidc', s($data->name)));
    }
}

echo $OUTPUT->header();
echo $OUTPUT->heading($heading);
$form->display();
echo $OUTPUT->footer();
