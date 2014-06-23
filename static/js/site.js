$(document).ready(function() {
    $('#f_register').bootstrapValidator({
        message: 'This value is not valid',
        feedbackIcons: {
            valid: 'glyphicon glyphicon-ok',
            invalid: 'glyphicon glyphicon-remove'
        },
        live: 'enabled',
        fields: {
            name: {
                validators: {
                    notEmpty: { message: 'Field cannot be empty' },
                    regexp: { regexp: '^[^ ]+ [^ ]+', message: 'Please enter your FULL name' }
                }
            },
            email: {
                validators: {
                    notEmpty: { message: 'Field canot be empty' },
                    emailAddress: { message: 'Please enter a valid email address' },
                    remote: { message: 'Already registered. Click <a href="javascript:send_reminder()">here</a> to retrieve your trial details.',
                              url: '/trials/_/checkemail' }
                }
            }
        }
    });
});

function on_dyn_poll_result(data, single_shot)
{
    $('#sp_expires').html(data.expires_in);
    if (data.autostop_in) {
        var text = data.autostop_in;
        text += ' (<a href="javascript:extend_autostop(\'' + data.id + '\')">extend</a>)'
        $('#sp_autostop').html(text);
    }
    if (data.status == 'BUILDING' || data.status == 'QUEUED') {
        var span = $('#sp_status');
        var current = span.html();
        if (current.startsWith(data.status)) {
            var ndots = current.length - data.status.length;
            ndots = (ndots == 5) ? 0 : ndots + 1;
        } else
            ndots = 0;
        span.html(data.status + '.'.repeat(ndots));
        $('#sp_ssh_addr').html('waiting' + '.'.repeat(ndots));
        $('#sp_http_url').html('waiting' + '.'.repeat(ndots));
        $('#sp_vnc_url').html('waiting' + '.'.repeat(ndots));
        if (!single_shot)
          window.setTimeout(function() { poll_dyn(data.id); }, 1000);
    } else {
        $('#sp_status').html(data.status);
        $('#sp_ssh_addr').html(data.ssh_addr);
        $('#sp_http_url').html('<a href="' + data.http_url + '">Open management interface</a>');
        $('#sp_vnc_url').html('<a href="/trials/' + data.id + '/vnc">Open VNC Console</a>');
        $('#p_intro').hide();
        $('#p_ready').show();
        if (!single_shot)
          window.setTimeout(function() { poll_dyn(data.id); }, 60000);
    }
}

function poll_dyn(id, single_shot)
{
    var url = '/trials/' + id + '/dyn';
    $.ajax(url, {type: 'GET', dataType: 'json',
                 success: function(data, status, xhr) {
                      on_dyn_poll_result(data, single_shot); }});
}

function show_message(message)
{
    $('#message_modal .modal-body').html(message);
    $('#message_modal').modal('show');
}

function send_reminder()
{
    var email = $('#f_register input[name=email]').val();
    $.ajax('/trials/_/remind', {data: {email: email}, type: 'POST',
                                success: function () {
                                    show_message('Email was sent succesfully'); },
                                error: function() {
                                    show_message('Error sending email'); }});
}

function extend_autostop(id)
{
    var url = '/trials/' + id + '/extend';
    $.ajax(url, {success: function() {
                    poll_dyn(id, true);
                    show_message('Autostop succesfully extended'); },
                 error: function() {
                    show_message('Error extending autostop'); } } );
}
