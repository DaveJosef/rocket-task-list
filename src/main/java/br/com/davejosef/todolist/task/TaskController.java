package br.com.davejosef.todolist.task;

import br.com.davejosef.todolist.utils.Utils;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/tasks")
public class TaskController {

    @Autowired
    private ITaskRepository taskRepository;

    @PostMapping("/")
    public ResponseEntity create(@RequestBody TaskModel taskModel, HttpServletRequest request) {

        var currentDate = LocalDateTime.now();
        if (currentDate.isAfter(taskModel.getStartAt()) || currentDate.isAfter(taskModel.getEndAt())) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body("A data de início e data de término devem ambas serem posteriores a data atual!");
        }

        if (taskModel.getStartAt().isAfter(taskModel.getEndAt())) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body("A data de início deve ser anterior a data de termino!");
        }

        taskModel.setId((UUID) request.getAttribute("userId"));
        var task = this.taskRepository.save(taskModel);
        return ResponseEntity.status(HttpStatus.OK).body(task);
    }

    @GetMapping("/")
    public List<TaskModel> list(HttpServletRequest request) {
        var userId = request.getAttribute("userId");
        var tasks = this.taskRepository.findByIdUser((UUID) userId);
        return tasks;
    }

    @PutMapping("/{id}")
    public ResponseEntity update(@RequestBody TaskModel taskModel, HttpServletRequest request, @PathVariable UUID id) {
        var task = this.taskRepository.findById(id).orElse(null);

        if (task == null) {
            return ResponseEntity
                    .status(HttpStatus.NOT_FOUND)
                    .body("Tarefa não encontrada");
        }

        var userId = request.getAttribute("userId");
        if (!userId.equals(task.getIdUser())) {
            return ResponseEntity
                    .status(HttpStatus.FORBIDDEN)
                    .body("User sem permissão");
        }

        Utils.copyNonNullProperties(taskModel, task);

        TaskModel taskUpdate = this.taskRepository.save(task);
        return ResponseEntity.status(HttpStatus.CREATED).body(taskUpdate);
    }

}
